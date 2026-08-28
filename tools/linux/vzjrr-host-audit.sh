#!/usr/bin/env bash
# vzjRR Security Assessment for FiveM - read-only Linux host persistence & access audit.
#
# Cleaning a FiveM resource tree does not evict an attacker. Re-infection after a
# "successful" cleanup almost always comes from something outside resources/:
# an SSH key, a cron job, a systemd unit, an extra privileged account, or stolen
# credentials that were never rotated. This script inspects those.
#
# STRICTLY READ-ONLY: it reads and reports. It changes nothing, kills nothing,
# deletes nothing, and contacts no network endpoint.
#
# Usage: ./vzjrr-host-audit.sh [SERVER_PATH] [OUT_DIR]
# Run as root for full coverage.

set -uo pipefail

CREDIT="vzjRR Security Assessment for FiveM"
SERVER_PATH="${1:-}"
OUT_DIR="${2:-$PWD/vzjrr-audit/$(date +%Y%m%d-%H%M%S)}"
WINDOW_DAYS="${WINDOW_DAYS:-45}"

mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/host-audit.md"

CRIT=0; HIGH=0
sec()  { printf '\n\033[36m=== %s ===\033[0m\n' "$1"; { echo; echo "## $1"; echo; } >> "$REPORT"; }
note() { echo "$1"; echo "$1" >> "$REPORT"; }
pre()  { echo '```' >> "$REPORT"; tee -a "$REPORT"; echo '```' >> "$REPORT"; }
flag() { # flag SEVERITY "item" "why"
  local sev="$1"
  case "$sev" in critical) CRIT=$((CRIT+1)); printf '\033[31m[CRITICAL]\033[0m %s\n' "$2";;
                 high)     HIGH=$((HIGH+1)); printf '\033[35m[HIGH]\033[0m %s\n' "$2";;
                 *)        printf '[%s] %s\n' "$sev" "$2";; esac
  echo "- **${sev^^}** — $2" >> "$REPORT"
  [ -n "${3:-}" ] && echo "  - _Why:_ $3" >> "$REPORT"
}

[ "$(id -u)" -eq 0 ] || echo "WARNING: not root - some checks will be incomplete."

{
  echo "# Linux Host Persistence & Access Audit"
  echo
  echo "- **Host:** $(hostname)"
  echo "- **Scanned (UTC):** $(date -u '+%Y-%m-%d %H:%M:%S')"
  echo "- **Kernel:** $(uname -a)"
  echo "- **Window:** last ${WINDOW_DAYS} days"
  echo
  echo "> Any confirmed critical finding here means file cleanup alone will not recover the"
  echo "> server. Close the access path and rotate the credentials, or the intrusion repeats."
} > "$REPORT"

# ------------------------------------------------------------------ 1. accounts
sec "1. Accounts and privilege"
note "Accounts with UID 0:"
awk -F: '$3==0 {print "  "$1" (uid 0, shell "$7")"}' /etc/passwd | pre
UID0=$(awk -F: '$3==0' /etc/passwd | wc -l)
[ "$UID0" -gt 1 ] && flag critical "$UID0 accounts have UID 0 (expected: 1, root)" \
  "An extra UID-0 account is full root access that survives every file cleanup."

note "Accounts with a login shell:"
awk -F: '$7 !~ /(nologin|false|sync)$/ {print "  "$1" -> "$7}' /etc/passwd | pre

note "sudo / wheel group members:"
{ getent group sudo; getent group wheel; getent group admin; } 2>/dev/null | pre

note "Passwords changed inside the window:"
CUTOFF_DAYS=$(( $(date +%s) / 86400 - WINDOW_DAYS ))
while IFS=: read -r u _ lastchg _; do
  [ -n "$lastchg" ] && [ "$lastchg" -gt "$CUTOFF_DAYS" ] 2>/dev/null && \
    flag high "password for '$u' changed $(( $(date +%s)/86400 - lastchg )) days ago" \
      "Credential change inside the intrusion window. If that was not you, the account is attacker-controlled."
done < /etc/shadow 2>/dev/null

# ------------------------------------------------------------------ 2. SSH
sec "2. SSH keys and configuration"
for home in /root /home/*; do
  ak="$home/.ssh/authorized_keys"
  [ -f "$ak" ] || continue
  n=$(grep -cvE '^\s*(#|$)' "$ak" 2>/dev/null || echo 0)
  flag critical "$ak contains $n key(s)" \
    "Every key here is permanent passwordless access. An attacker key is completely unaffected by cleaning resource files - it is the most common cause of re-infection on Linux hosts. Verify each fingerprint against keys you personally hold."
  ssh-keygen -lf "$ak" 2>/dev/null | sed 's/^/    /' | pre
done
note "sshd effective settings:"
grep -Ei '^\s*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port|AllowUsers|AllowGroups|PermitEmptyPasswords)' \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | pre
grep -qEi '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config 2>/dev/null && \
  flag high "PermitRootLogin yes" "Direct root SSH login is enabled."
grep -qEi '^\s*PasswordAuthentication\s+yes' /etc/ssh/sshd_config 2>/dev/null && \
  flag high "PasswordAuthentication yes" "Password SSH is brute-forceable; prefer keys only."

# ------------------------------------------------------------------ 3. scheduled execution
sec "3. Cron, at, and systemd timers"
note "User crontabs:"
for u in $(cut -f1 -d: /etc/passwd); do
  c=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)')
  [ -n "$c" ] && { echo "  [$u]"; echo "$c" | sed 's/^/    /'; }
done | pre
note "System cron:"
cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -vE '^\s*(#|$)' | pre
SUS='curl|wget|base64|bash -i|nc |ncat|/dev/tcp/|python -c|perl -e|eval|chmod \+x|\.onion|pastebin|\-panel\.'
if crontab -l 2>/dev/null | grep -qE "$SUS" || grep -rqE "$SUS" /etc/cron* 2>/dev/null; then
  flag critical "cron entry uses download/execute tradecraft" \
    "A cron job that fetches and runs remote content re-installs the backdoor on a schedule - this is exactly how a cleaned server becomes re-infected."
  grep -rE "$SUS" /etc/cron* 2>/dev/null | head -20 | pre
fi
note "systemd timers:"
systemctl list-timers --all --no-pager 2>/dev/null | head -30 | pre

# ------------------------------------------------------------------ 4. services
sec "4. systemd units"
note "Non-vendor enabled units:"
systemctl list-unit-files --state=enabled --no-pager 2>/dev/null | head -60 | pre
note "Unit files modified inside the window:"
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
     -name '*.service' -mtime -"$WINDOW_DAYS" 2>/dev/null | pre
for f in $(find /etc/systemd/system -name '*.service' -mtime -"$WINDOW_DAYS" 2>/dev/null); do
  grep -qE "$SUS" "$f" && flag critical "systemd unit $f uses download/execute tradecraft" \
    "Service-based persistence that re-installs the payload."
done

# ------------------------------------------------------------------ 5. shell rc persistence
sec "5. Shell startup persistence"
for f in /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc /home/*/.bash_profile /home/*/.profile /etc/profile /etc/profile.d/*; do
  [ -f "$f" ] || continue
  if grep -qE "$SUS" "$f" 2>/dev/null; then
    flag high "$f contains download/execute patterns" "Login-triggered persistence."
    grep -nE "$SUS" "$f" | head -5 | pre
  fi
done

# ------------------------------------------------------------------ 6. binaries
sec "6. SUID binaries and recent binary changes"
note "Unusual SUID binaries:"
find / -xdev -perm -4000 -type f 2>/dev/null | \
  grep -vE '^/(usr/)?(bin|sbin|lib|libexec)/' | pre
note "Files in system bin dirs modified inside the window:"
find /usr/bin /usr/sbin /bin /sbin -type f -mtime -"$WINDOW_DAYS" 2>/dev/null | head -40 | pre
note "World-writable files in /etc:"
find /etc -xdev -type f -perm -0002 2>/dev/null | head -20 | pre

# ------------------------------------------------------------------ 7. network
sec "7. Listening ports and connections"
note "Listening sockets:"
(ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null) | pre
if (ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null) | grep -qE ':40120\b.*0\.0\.0\.0|:40120\b.*\*:'; then
  flag high "txAdmin web panel (40120) bound to all interfaces" \
    "If port 40120 is reachable from the internet it is a login page for your entire server. Restrict it to a VPN, an IP allowlist, or an authenticated reverse proxy."
fi
note "Established connections:"
(ss -tanp state established 2>/dev/null || netstat -tanp 2>/dev/null | grep ESTAB) | head -60 | pre
note "Firewall:"
{ iptables -S 2>/dev/null | head -40; ufw status verbose 2>/dev/null; } | pre

# ------------------------------------------------------------------ 8. processes
sec "8. Processes"
note "Processes running from writable/temp locations:"
ps -eo pid,user,etime,args --no-headers 2>/dev/null | \
  grep -E '/tmp/|/dev/shm/|/var/tmp/|\s\./' | grep -v grep | pre
ps -eo args --no-headers 2>/dev/null | grep -E '/tmp/|/dev/shm/' | grep -v grep | head -1 | grep -q . && \
  flag critical "process executing from a temp directory" \
    "Legitimate server software does not run from /tmp or /dev/shm."
note "Deleted-but-running binaries (classic hidden malware):"
ls -l /proc/*/exe 2>/dev/null | grep -i deleted | pre
ls -l /proc/*/exe 2>/dev/null | grep -qi deleted && \
  flag critical "a running process's binary has been deleted from disk" \
    "The file is gone but the process is live - deliberate anti-forensics."

# ------------------------------------------------------------------ 9. logins
sec "9. Login history"
note "Recent successful logins:"
last -a -n 40 2>/dev/null | pre
note "Failed login volume:"
{ lastb -n 5 2>/dev/null | head -5; echo "total failed: $(lastb 2>/dev/null | wc -l)"; } | pre

# ------------------------------------------------------------------ 10. FiveM config
sec "10. txAdmin and server configuration"
if [ -n "$SERVER_PATH" ] && [ -d "$SERVER_PATH" ]; then
  note "admins.json locations:"
  find "$SERVER_PATH" "$(dirname "$SERVER_PATH")" -maxdepth 6 -name admins.json 2>/dev/null | sort -u | while read -r af; do
    flag critical "txAdmin admin store: $af (modified $(stat -c %y "$af" 2>/dev/null | cut -d. -f1))" \
      "REVIEW EVERY ENTRY BY HAND. An attacker-added admin here is standing access to your whole server and is completely unaffected by cleaning resource files. This is the number one cause of re-infection after a 'successful' cleanup."
    python3 -c "
import json,sys
for a in json.load(open('$af')):
    print('    admin:', a.get('name'), 'master=', a.get('master'), 'providers=', list((a.get('providers') or {}).keys()))
" 2>/dev/null | pre
  done

  note "server.cfg access-control and secret lines (values redacted):"
  find "$SERVER_PATH" -maxdepth 3 -name '*.cfg' 2>/dev/null | while read -r c; do
    grep -nE '^\s*(add_principal|add_ace|exec)\s' "$c" 2>/dev/null | sed "s|^|  $c:|"
  done | pre
  find "$SERVER_PATH" -maxdepth 3 -name '*.cfg' 2>/dev/null | while read -r c; do
    grep -qE '^\s*add_(principal|ace)\s' "$c" && flag critical "ACE/principal grants in $c" \
      "Every identifier granted here has elevated in-game and console rights. One line you do not recognise is a permanent backdoor."
    grep -qE 'sv_licenseKey|steam_webApiKey|mysql_connection_string|rcon_password' "$c" && \
      flag critical "secrets stored in plaintext in $c" \
      "The attacker read this file. Treat every credential in it as compromised: revoke and regenerate the FiveM license key in Keymaster, rotate the DB password, rotate RCON, regenerate Discord and Steam tokens."
    grep -qE '[a-z0-9_-]{2,30}-panel\.(me|xyz|cc|su|ru|top)' "$c" && \
      flag critical "panel C2 domain referenced in $c" "Direct C2 reference in server configuration."
  done
else
  echo "No SERVER_PATH given - skipping txAdmin/server.cfg checks."
fi

# ------------------------------------------------------------------ verdict
if   [ "$CRIT" -gt 0 ]; then VERDICT="HOST PERSISTENCE / STANDING ACCESS INDICATORS PRESENT - assume the attacker can return"; RC=2
elif [ "$HIGH" -gt 0 ]; then VERDICT="REVIEW REQUIRED - high-severity host findings"; RC=1
else VERDICT="No host persistence indicators detected in the checks performed (not a proof of cleanliness)"; RC=0; fi

{ echo; echo "## Verdict"; echo; echo "**$VERDICT**"; echo;
  echo "Critical: $CRIT — High: $HIGH"; echo; echo "---"; echo "Prepared by: $CREDIT"; } >> "$REPORT"

printf '\n\033[1mVERDICT: %s\033[0m\n' "$VERDICT"
echo "Report: $REPORT"
echo "Prepared by: $CREDIT"
exit $RC
