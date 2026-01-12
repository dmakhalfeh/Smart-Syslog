import os
import re
import json
import time
import ipaddress
from typing import Any, Dict, Optional, Tuple

from redis import Redis
from redis.exceptions import ResponseError, BusyLoadingError, ConnectionError, TimeoutError

# -----------------------------
# Config (env-driven)
# -----------------------------
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

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

IGNORE_CIDRS_ENV = os.environ.get("IGNORE_CIDRS", "").strip()

# -----------------------------
# Parsing helpers
# -----------------------------
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# Detect explicit source/destination IP inside MESSAGE strings
# Supports: src_ip="1.2.3.4" src=1.2.3.4 source=1.2.3.4 client_ip=...
MSG_SRC_RE = re.compile(
    r"""(?ix)
    \b(?:src_ip|srcip|src|sourceip|source|client_ip|clientip|remote_ip|remoteip)\s*=\s*
    (?:"|')?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?:"|')?
    """
)

# Supports: dst_ip="1.2.3.4" dst=1.2.3.4 destination=1.2.3.4
MSG_DST_RE = re.compile(
    r"""(?ix)
    \b(?:dst_ip|dstip|dst|destinationip|destination)\s*=\s*
    (?:"|')?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?:"|')?
    """
)

SRC_KEYS = (
    "src_ip", "srcip", "src", "sourceip", "source", "client_ip", "remote_ip",
    "SRC_IP", "SRCIP", "SRC", "SOURCEIP", "SOURCE", "CLIENT_IP", "REMOTE_IP",
)
DST_KEYS = (
    "dst_ip", "dstip", "dst", "destinationip", "destination",
    "DST_IP", "DSTIP", "DST", "DESTINATIONIP", "DESTINATION",
)
GENERIC_IP_KEYS = ("ip", "addr", "IP", "ADDR")

ATTACKY_HINTS = ("blocked", "drop", "deny", "denied", "invalid", "failed", "attack", "scan", "bruteforce", "intrusion")


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
            pass
    return nets


IGNORE_CIDRS = parse_cidrs_list(IGNORE_CIDRS_ENV)


def is_ignored_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return True

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
    # Redis can be "busy loading" during startup (RDB/AOF restore).
    # Retry so the worker doesn't die on boot.
    delay = 0.5
    for attempt in range(1, 31):
        try:
            r.xgroup_create(name=RAW_STREAM, groupname=RAW_GROUP, id="$", mkstream=True)
            return
        except ResponseError as e:
            if "BUSYGROUP" in str(e):
                return
            raise
        except (BusyLoadingError, ConnectionError, TimeoutError) as e:
            print(f"[worker] Redis not ready ({type(e).__name__}); retry {attempt}/30 in {delay:.1f}s")
            time.sleep(delay)
            delay = min(delay * 1.4, 5.0)
    raise RuntimeError("Redis not ready after retries")


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
      2) structured DST fields
      3) parse MESSAGE for src/dst markers (most important for your firewall logs)
      4) generic fields (unknown role)
      5) scan message-ish fields (unknown role)
      6) scan all string fields (unknown role)
    """
    # 1) Structured SRC fields
    for k in SRC_KEYS:
        ip = _ip_from_field(event, k)
        if ip:
            return ip, f"field:{k}", "src"

    # 2) Structured DST fields
    for k in DST_KEYS:
        ip = _ip_from_field(event, k)
        if ip:
            return ip, f"field:{k}", "dst"

    # 3) Parse MESSAGE for src/dst markers
    msg = ""
    for k in ("MESSAGE", "message", "MSG", "LEGACY_MSGHDR"):
        if isinstance(event.get(k), str):
            msg = event[k]
            break

    if msg:
        m = MSG_SRC_RE.search(msg)
        if m:
            ip = m.group("ip")
            return ip, "msg:src_marker", "src"
        m = MSG_DST_RE.search(msg)
        if m:
            ip = m.group("ip")
            return ip, "msg:dst_marker", "dst"

    # 4) Generic fields
    for k in GENERIC_IP_KEYS:
        ip = _ip_from_field(event, k)
        if ip:
            return ip, f"field:{k}", "unknown"

    # 5) Scan message-ish fields for any IP
    if msg:
        m = IPV4_RE.search(msg)
        if m:
            return m.group(0), "msg:any_ip", "unknown"

    # 6) Scan all fields
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
    # Your stream entries are {event: "<json>"}
    event_json = fields.get(b"event")
    if not event_json:
        r.xack(RAW_STREAM, RAW_GROUP, msg_id)
        return

    raw_str = event_json.decode("utf-8", errors="replace")
    raw_event = safe_json_loads(raw_str) or {"raw": raw_str}

    ip, method, role = extract_ip(raw_event)

    # Always write normalized event
    normalized = normalize_event(raw_event, ip, method, role)
    r.xadd(PARSED_STREAM, normalized)

    # Score only src + non-local
    if ip and role == "src" and not is_ignored_ip(ip):
        inc = score_increment_for_event(raw_event)
        new_score = r.zincrby(SCORE_ZSET, inc, ip)

        r.hset(SCORE_HASH, f"{ip}:last_seen", str(int(now_ts())))
        r.hset(SCORE_HASH, f"{ip}:last_inc", str(inc))
        r.expire(SCORE_HASH, SCORE_TTL_SECONDS)

        if float(new_score) >= float(SCORE_BLOCK_THRESHOLD):
            maybe_emit_block(r, ip, float(new_score))

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
        f"ignore_local_private=yes ignore_dst=yes ignore_cidrs={IGNORE_CIDRS_ENV or '(none)'} "
        f"threshold={SCORE_BLOCK_THRESHOLD}"
    )

    while True:
        try:
            resp = r.xreadgroup(
                groupname=RAW_GROUP,
                consumername=CONSUMER_NAME,
                streams={RAW_STREAM: ">"},
                count=BATCH_COUNT,
                block=BLOCK_MS,
            )
        except (BusyLoadingError, ConnectionError, TimeoutError) as e:
            print(f"[worker] read error ({type(e).__name__}); sleeping 1s")
            time.sleep(1)
            continue

        if not resp:
            continue

        for _stream_name, messages in resp:
            for msg_id_b, fields in messages:
                msg_id = msg_id_b.decode("utf-8", errors="replace")
                try:
                    process_message(r, msg_id, fields)
                except Exception as e:
                    # Don't ACK on failure
                    print(f"[worker] ERROR processing {msg_id}: {e}")


if __name__ == "__main__":
    main()
