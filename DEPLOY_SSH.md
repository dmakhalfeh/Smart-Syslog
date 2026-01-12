# SSH Authentication for Deployment

## Current Behavior

When you run `./deploy.sh`, it will **prompt for your SSH password** multiple times (once for each command). You'll need to enter it each time.

## Option 1: Use SSH Keys (Recommended - Passwordless)

Set up SSH keys so you don't need to enter a password every time:

### Step 1: Generate SSH key (if you don't have one)
```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
# Press Enter to accept default location (~/.ssh/id_ed25519)
# Optionally set a passphrase, or press Enter for no passphrase
```

### Step 2: Copy your public key to the server
```bash
ssh-copy-id root@10.0.0.61
# Enter password when prompted (this is the last time!)
```

**Or manually:**
```bash
cat ~/.ssh/id_ed25519.pub | ssh root@10.0.0.61 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

### Step 3: Test passwordless login
```bash
ssh root@10.0.0.61
# Should connect without asking for password
```

Now when you run `./deploy.sh`, it won't ask for a password!

---

## Option 2: Use sshpass (Less Secure - Not Recommended)

**⚠️ Warning:** This stores passwords in plain text. Only use for testing!

### Install sshpass on Mac:
```bash
brew install hudochenkov/sshpass/sshpass
```

### Modify deploy.sh to use password:

You would need to add `sshpass -p 'YOUR_PASSWORD'` before each ssh/rsync command, but this is **not recommended** for security reasons.

---

## Option 3: Run Manually with Password Prompts

Just run the script normally, and enter the password when prompted:

```bash
./deploy.sh
```

You'll be prompted for password several times. This is fine for one-time deployments.

---

## Option 4: Use SSH Config File

Create/edit `~/.ssh/config`:

```bash
nano ~/.ssh/config
```

Add:
```
Host smart-syslog-server
    HostName 10.0.0.61
    User root
    IdentityFile ~/.ssh/id_ed25519
    # Or use password authentication:
    # PreferredAuthentications password
```

Then you can use:
```bash
ssh smart-syslog-server
```

---

## Quick Setup SSH Keys (Recommended)

Run these commands:

```bash
# 1. Generate key (if needed)
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""

# 2. Copy to server (will prompt for password once)
ssh-copy-id root@10.0.0.61

# 3. Test
ssh root@10.0.0.61 "echo 'SSH keys working!'"

# 4. Now run deploy script (no password needed)
./deploy.sh
```

---

## If You Forget Your Password

If you've lost access to the server, you'll need to:
- Use the server's console/KVM if available
- Contact your hosting provider for root access
- Use recovery/reset mechanisms provided by your hosting provider
