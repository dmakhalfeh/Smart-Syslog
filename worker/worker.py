import os
import re
import json
import time
import ipaddress
from typing import Any, Dict, Optional, Tuple

from redis import Redis
from redis.exceptions import ResponseError

# -----------------------------
# Config (env-driven)
# -----------------------------
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

RAW_STREAM = os.environ.get("RAW_STREAM", "syslog:raw")
RAW_GROUP = os.environ.get("RAW_GROUP", "syslog-workers")
CONSUMER_NAME = os.environ.get("CONSUMER_NAME", "worker-1")

PARSED_STREAM = os.environ.get("PARSED_STREAM", "syslog:parsed")
BLOCK_STREAM = os.environ.get("BLOCK_STREAM", "syslog:blocklist")

SCORE_ZSET = os.environ.get("SCORE_ZSET", "ip:score")
SCORE_HASH = os.environ.get("SCORE_HASH", "ip:score:meta")

SCORE_INCREMENT_DEFAULT = int(os.environ.get("SCORE_INCREMENT_DEFAULT", "1"))
SCORE_BLOCK_THRESHOLD = int(os.environ.get("SCORE_BLOCK_THRESHOLD", "15"))
SCORE_TTL_SECONDS = int(os.environ.get("SCORE_TTL_SECONDS", "86400"))  # 1 day (soft)
BLOCK_TTL_SECONDS = int(os.environ.get("BLOCK_TTL_SECONDS", "3600"))   # suggested block duration

BATCH_COUNT = int(os.environ.get("BATCH_COUNT", "50"))
BLOCK_MS = int(os.environ.get("BLOCK_MS", "2000"))

# Optional: add your own "never score/block these" CIDRs
# Example: "203.0.113.5/32,10.10.0.0/16"
IGNORE_CIDRS_ENV = os.environ.get("IGNORE_CIDRS", "").strip()

# -----------------------------
# Parsing helpers
# -----------------------------
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# Prefer SRC scoring; ignore DST scoring.
SRC_KEYS = (
    "srcip", "src", "sourceip", "client_ip", "remote_ip",
    "SRCIP", "SRC", "SOURCEIP", "CLIENT_IP", "REMOTE_IP",
)
DST_KEYS = (
    "dstip", "dst", "destinationip",
    "DSTIP", "DST", "DESTINATIONIP",
)

# Fallback "any IP" keys (unknown role)
GENERIC_IP_KEYS = ("ip", "addr", "IP", "ADDR")

ATTACKY_HINTS = ("blocked", "drop", "deny", "invalid", "failed", "attack", "scan", "bruteforce", "intrusion")


def now_ts() -> float:
    return time.time()


def safe_json_loads(s: str) -> Optional[Dict[str, Any]]:
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else None
    except Exception:
        return None


def parse_cidrs_list(env_value: str) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    if not env_value:
        return nets
    for part in env_value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            # ignore bad entries rather than killing the worker
            pass
    return nets


IGNORE_CIDRS = parse_cidrs_list(IGNORE_CIDRS_ENV)


def is_ignored_ip(ip: str) -> bool:
    """
    Ignore local/private/non-routable IPs by default:
      - private (RFC1918)
      - loopback
      - link-local
      - multicast / reserved
    Plus any custom IGNORE_CIDRS.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return True  # malformed => ignore

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
    ):
        return True

    for net in IGNORE_CIDRS:
        if ip_obj in net:
            return True

    return False


def ensure_group(r: Redis) -> None:
    try:
        r.xgroup_create(name=RAW_STREAM, groupname=RAW_GROUP, id="$", mkstream=True)
    except ResponseError as e:
        if "BUSYGROUP" in str(e):
            return
        raise


def _ip_from_field(event: Dict[str, Any], key: str) -> Optional[str]:
    v = event.get(key)
    if isinstance(v, str):
        m = IPV4_RE.search(v)
        if m:
            return m.group(0)
    return None


def extract_ip(event: Dict[str, Any]) -> Tuple[Optional[str], str, str]:
    """
    Returns (ip, method, role)
    role = "src" | "dst" | "unknown" | "none"
    Strategy:
      1) structured SRC fields (preferred)
      2) structured DST fields (identified but ignored for scoring)
      3) generic fields (unknown role)
      4) message-ish fields (unknown role)
      5) scan all string fields (unknown role)
    """
    # 1) SRC fields
    for k in SRC_KEYS:
        ip = _ip_from_field(event, k)
        if ip:
            return ip, f"field:{k}", "src"

    # 2) DST fields
    for k in DST_KEYS:
        ip = _ip_from_field(event, k)
        if ip:
            return ip, f"field:{k}", "dst"

    # 3) generic fields
    for k in GENERIC_IP_KEYS:
        ip = _ip_from_field(event, k)
        if ip:
            return ip, f"field:{k}", "unknown"

    # 4) message-like fields
    for k in ("MESSAGE", "MSG", "message", "LEGACY_MSGHDR"):
        v = event.get(k)
        if isinstance(v, str):
            m = IPV4_RE.search(v)
            if m:
                return m.group(0), f"msg:{k}", "unknown"

    # 5) scan all fields
    for k, v in event.items():
        if isinstance(v, str):
            m = IPV4_RE.search(v)
            if m:
                return m.group(0), f"scan:{k}", "unknown"

    return None, "none", "none"


def score_increment_for_event(event: Dict[str, Any]) -> int:
    inc = SCORE_INCREMENT_DEFAULT
    msg = ""
    for k in ("MESSAGE", "message"):
        if isinstance(event.get(k), str):
            msg = event[k]
            break

    low = msg.lower()
    if any(h in low for h in ATTACKY_HINTS):
        inc += 2
    return inc


def normalize_event(raw_event: Dict[str, Any], ip: Optional[str], ip_method: str, role: str) -> Dict[str, Any]:
    msg = raw_event.get("MESSAGE") or raw_event.get("message") or raw_event.get("MSG") or ""
    program = raw_event.get("PROGRAM") or raw_event.get("program") or ""
    host = raw_event.get("HOST") or raw_event.get("host") or raw_event.get("HOST_FROM") or ""

    ignored = False
    if ip:
        # Ignore if not source, or if local/private/etc.
        ignored = (role != "src") or is_ignored_ip(ip)

    return {
        "ts": str(now_ts()),
        "host": str(host),
        "program": str(program),
        "message": str(msg),
        "ip": ip or "",
        "ip_role": role,
        "ip_method": ip_method,
        "ignored_ip": "1" if ignored else "0",
        "raw": json.dumps(raw_event, ensure_ascii=False),
    }


def maybe_emit_block(r: Redis, ip: str, score: float) -> None:
    """
    Emit a block instruction once per IP (simple de-dupe using SCORE_HASH).
    """
    meta_key = f"{ip}:blocked_at"
    if r.hget(SCORE_HASH, meta_key) is not None:
        return

    payload = {
        "ts": str(now_ts()),
        "ip": ip,
        "score": str(score),
        "action": "block",
        "ttl_seconds": str(BLOCK_TTL_SECONDS),
        "reason": "score_threshold",
    }
    r.xadd(BLOCK_STREAM, payload)
    r.hset(SCORE_HASH, meta_key, str(int(now_ts())))
    r.expire(SCORE_HASH, SCORE_TTL_SECONDS)


def process_message(r: Redis, msg_id: str, fields: Dict[bytes, bytes]) -> None:
    """
    Redis Stream fields look like: {b"event": b"<json>"} from redis-writer.
    """
    event_json = fields.get(b"event")
    if not event_json:
        r.xack(RAW_STREAM, RAW_GROUP, msg_id)
        return

    raw_str = event_json.decode("utf-8", errors="replace")
    raw_event = safe_json_loads(raw_str) or {"raw": raw_str}

    ip, method, role = extract_ip(raw_event)

    # Always write normalized event (even if IP ignored / absent)
    normalized = normalize_event(raw_event, ip, method, role)
    r.xadd(PARSED_STREAM, normalized)

    # Score only if IP exists, is source, and is NOT local/private/etc.
    if ip and role == "src" and not is_ignored_ip(ip):
        inc = score_increment_for_event(raw_event)
        new_score = r.zincrby(SCORE_ZSET, inc, ip)

        r.hset(SCORE_HASH, f"{ip}:last_seen", str(int(now_ts())))
        r.hset(SCORE_HASH, f"{ip}:last_inc", str(inc))
        r.expire(SCORE_HASH, SCORE_TTL_SECONDS)

        if new_score >= SCORE_BLOCK_THRESHOLD:
            maybe_emit_block(r, ip, float(new_score))

    # ACK only after successful processing
    r.xack(RAW_STREAM, RAW_GROUP, msg_id)


def main() -> None:
    r = Redis.from_url(
        REDIS_URL,
        decode_responses=False,
        socket_timeout=5,
        socket_connect_timeout=5,
    )

    ensure_group(r)
    print(
        f"[worker] consuming stream={RAW_STREAM} group={RAW_GROUP} consumer={CONSUMER_NAME} "
        f"ignore_local_private=yes ignore_dst=yes ignore_cidrs={IGNORE_CIDRS_ENV or '(none)'}"
    )

    while True:
        resp = r.xreadgroup(
            groupname=RAW_GROUP,
            consumername=CONSUMER_NAME,
            streams={RAW_STREAM: ">"},
            count=BATCH_COUNT,
            block=BLOCK_MS,
        )

        if not resp:
            continue

        for _stream_name, messages in resp:
            for msg_id_b, fields in messages:
                msg_id = msg_id_b.decode("utf-8", errors="replace")
                try:
                    process_message(r, msg_id, fields)
                except Exception as e:
                    # Don't ACK on failure; it stays pending for retry/claim.
                    print(f"[worker] ERROR processing {msg_id}: {e}")


if __name__ == "__main__":
    main()
