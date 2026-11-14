#!/usr/bin/env bash
# audit_mail.sh - READ-ONLY security audit for the Ubuntu mail server (Postfix + Dovecot)
# Usage: sudo ./audit_mail.sh [-p "22 25 465 587 143 993 80 443"]
#   -p PORTS   space-separated list of ports you EXPECT to be listening
#
# Changes nothing on the box. The only file it writes is the report:
#   /root/audit-<host>-<timestamp>.txt
# Every line starting with [!!] is something to investigate. All findings are
# repeated in a summary at the end. A finding is "look at this", not "this is
# definitely evil" - some will be normal for your box.

set -uo pipefail

EXPECTED_PORTS="22 25 465 587 143 993 110 995 80 443"
while getopts "p:h" opt; do
  case "$opt" in
    p) EXPECTED_PORTS="$OPTARG" ;;
    *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo -i first) - most checks need to read root-only files." >&2
  exit 1
fi

HOST="$(hostname -s)"
STAMP="$(date +%F-%H%M%S)"
REPORT="/root/audit-$HOST-$STAMP.txt"
umask 077

# Findings go to a temp file (not an array) so flags raised inside piped
# while-loops, which run in subshells, still reach the summary.
FLAGFILE="$(mktemp)"
trap 'rm -f "$FLAGFILE"' EXIT
flag()    { echo "[!!] $*"; echo "$*" >>"$FLAGFILE"; }
ok()      { echo "[ok] $*"; }
info()    { echo "     $*"; }
section() { printf '\n========== %s ==========\n' "$*"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# Patterns that show up in backdoors / reverse shells
BADCMD='curl[[:space:]]|wget[[:space:]]|[[:space:]]nc[[:space:]]|ncat|socat|/dev/tcp/|/dev/udp/|bash -i|sh -i|mkfifo|base64 -d|base64 --decode|python[0-9.]* -c|perl -e|php -r'

main() {
  echo "Mail server audit - $HOST - $(date)"
  echo "Kernel: $(uname -r)   OS: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  echo "IPs: $(hostname -I 2>/dev/null)"
  echo "Uptime: $(uptime -p 2>/dev/null)"
  echo "Expected ports: $EXPECTED_PORTS"

  # ------------------------------------------------------------------------
  section "1. ACCOUNTS"

  # Any UID 0 account other than root is a backdoor root account
  while IFS=: read -r u _ uid _; do
    [[ "$uid" == 0 && "$u" != root ]] && flag "Extra UID 0 (root) account: $u"
  done </etc/passwd

  # Accounts with a real shell. Service accounts (UID < 1000) shouldn't have one.
  echo "Accounts with a login shell:"
  while IFS=: read -r u _ uid _ _ home shell; do
    case "$shell" in */nologin|*/false|/bin/sync|*/halt|*/shutdown|"") continue ;; esac
    info "$u (uid $uid) shell=$shell home=$home"
    if (( uid > 0 && uid < 1000 )); then
      flag "Service account with a login shell: $u ($shell)"
    fi
  done </etc/passwd

  # Empty password = log in with no password; usable password on a service account = suspicious
  while IFS=: read -r u hash _; do
    uid="$(id -u "$u" 2>/dev/null || echo 9999)"
    if [[ -z "$hash" ]]; then
      flag "Account with EMPTY password: $u"
    elif [[ "$hash" != \!* && "$hash" != \** ]]; then
      if (( uid > 0 && uid < 1000 )); then
        flag "Service account has a usable password: $u"
      else
        info "Has a usable password: $u"
      fi
    fi
  done </etc/shadow

  echo "Admin group members:"
  for g in sudo admin wheel; do
    line="$(getent group "$g")" && info "$line"
  done

  # sudoers: NOPASSWD and anything beyond the stock root/%sudo/%admin lines
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    grep -nE '^[^#]*NOPASSWD' "$f" 2>/dev/null | while IFS= read -r l; do
      flag "NOPASSWD sudo rule in $f: $l"
    done
    grep -nE '^[^#[:space:]]' "$f" 2>/dev/null \
      | grep -vE ':(Defaults|@include|#include|root[[:space:]]|%sudo[[:space:]]|%admin[[:space:]])' \
      | grep -v NOPASSWD | while IFS= read -r l; do
        flag "Non-default sudoers line in $f: $l"
      done
  done
  if [[ -d /etc/sudoers.d ]]; then
    echo "Files in /etc/sudoers.d:"
    ls -la /etc/sudoers.d | sed 's/^/     /'
  fi

  # SSH keys: every key here is a password-less way in
  echo "SSH authorized_keys files:"
  while IFS= read -r f; do
    n="$(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null || true)"
    [[ "$n" -gt 0 ]] || { info "$f (empty)"; continue; }
    flag "$f has $n key(s) - confirm each is your team's:"
    grep -vE '^[[:space:]]*(#|$)' "$f" | awk '{print "       key comment: " $NF}'
    [[ "$f" == *authorized_keys2 ]] && flag "authorized_keys2 file exists (common hiding spot): $f"
  done < <(find / \( -path /proc -o -path /sys -o -path /run \) -prune -o -name 'authorized_keys*' -type f -print 2>/dev/null)

  echo "Last modified:"
  stat -c '     %y  %n' /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null

  # ------------------------------------------------------------------------
  section "2. LOGINS AND SESSIONS"
  echo "Logged in now:"; who | sed 's/^/     /'
  echo "Recent logins:"; last -n 15 -a 2>/dev/null | sed 's/^/     /'
  if [[ -f /var/log/auth.log ]]; then
    fails="$(grep -c 'Failed password' /var/log/auth.log 2>/dev/null || true)"
    info "Failed SSH password attempts in auth.log: ${fails:-0}"
    echo "Last accepted SSH logins:"
    grep 'Accepted' /var/log/auth.log 2>/dev/null | tail -n 10 | sed 's/^/     /'
  fi

  # ------------------------------------------------------------------------
  section "3. NETWORK"
  if have ss; then
    while read -r proto laddr proc; do
      port="${laddr##*:}"
      addr="${laddr%:*}"
      case "$addr" in 127.*|\[::1\]|::1|*%lo) continue ;; esac   # loopback-only is fine
      if [[ " $EXPECTED_PORTS " == *" $port "* ]]; then
        ok "$proto $laddr $proc"
      else
        flag "Unexpected port open to the network: $proto $laddr $proc"
      fi
    done < <(ss -Htulpn 2>/dev/null | awk '{print $1, $5, $7}')
  else
    flag "ss not found - can't check listening ports"
  fi

  echo "Firewall:"
  if have ufw; then
    st="$(ufw status 2>/dev/null | head -n1)"
    info "ufw: $st"
    [[ "$st" == *inactive* ]] && flag "ufw firewall is INACTIVE"
  fi
  have iptables && info "iptables rules: $(iptables -S 2>/dev/null | wc -l) lines (full list in appendix)"

  # ------------------------------------------------------------------------
  section "4. PROCESSES"
  # Programs running from temp dirs, or whose file was deleted after launch
  for p in /proc/[0-9]*; do
    exe="$(readlink "$p/exe" 2>/dev/null)" || continue
    case "$exe" in
      /tmp/*|/var/tmp/*|/dev/shm/*|*"(deleted)")
        cmd="$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null | cut -c1-120)"
        flag "PID ${p#/proc/} runs $exe :: $cmd  (deleted can also mean upgraded but not restarted)"
        ;;
    esac
  done

  # A shell/interpreter owned by a service account usually means a webshell or exploit
  ps -eo user=,pid=,ppid=,comm=,args= 2>/dev/null | awk '
    $1 ~ /^(www-data|postfix|dovecot|dovenull|nobody|mail|vmail|daemon)$/ &&
    $4 ~ /^(sh|bash|dash|zsh|nc|ncat|socat|python[0-9.]*|perl|php[0-9.]*|ruby)$/ {
      out=""; for (i=5;i<=NF;i++) out=out" "$i; print $1, "pid", $2, "ppid", $3, ":"out }' \
  | while IFS= read -r l; do flag "Service account running a shell/interpreter: $l"; done

  # ------------------------------------------------------------------------
  section "5. PERSISTENCE"

  echo "User crontabs:"
  while IFS=: read -r u _; do
    c="$(crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')"
    [[ -z "$c" ]] && continue
    if [[ "$u" == root ]]; then info "root crontab:"; else flag "Crontab for $u:"; fi
    echo "$c" | sed 's/^/       /'
  done </etc/passwd

  grep -rnE "$BADCMD" /etc/crontab /etc/cron.* /var/spool/cron 2>/dev/null | while IFS= read -r l; do
    flag "Suspicious command in cron: $l"
  done
  echo "Files in /etc/cron.d (newest first):"
  ls -lt /etc/cron.d 2>/dev/null | tail -n +2 | sed 's/^/     /'

  # Unit files that are real files in /etc/systemd/system were added by hand, not by a package
  find /etc/systemd/system -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) \
       ! -name 'snap*' 2>/dev/null | while IFS= read -r f; do
    flag "Hand-made systemd unit $f :: $(grep -hE '^(ExecStart|OnCalendar|OnBootSec|ListenStream)=' "$f" | head -n2 | tr '\n' ' ')"
  done
  find /root /home -path '*/.config/systemd/user/*' -type f 2>/dev/null | while IFS= read -r f; do
    flag "User-level systemd unit: $f"
  done

  if [[ -s /etc/ld.so.preload ]]; then
    flag "/etc/ld.so.preload is not empty (rootkit trick): $(tr '\n' ' ' </etc/ld.so.preload)"
  else
    ok "/etc/ld.so.preload empty or missing"
  fi
  [[ -x /etc/rc.local ]] && grep -qvE '^[[:space:]]*(#|$|exit 0)' /etc/rc.local && \
    flag "/etc/rc.local has commands - review it"

  # Login scripts run every time someone logs in - classic place for reverse shells and alias hijacks
  grep -nE "$BADCMD|alias[[:space:]]+(sudo|su|ls|ps|ss|netstat|top|cat|passwd)=" \
    /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/environment \
    /root/.bashrc /root/.profile /root/.bash_profile \
    /home/*/.bashrc /home/*/.profile /home/*/.bash_profile 2>/dev/null \
    | grep -v -- "--color=auto'" | while IFS= read -r l; do
    flag "Suspicious line in a login script: $l"
  done

  # PAM backdoors: pam_exec runs programs at login, "sufficient pam_permit" lets anyone in
  grep -rnE '^[^#]*pam_exec|^[^#]*sufficient[[:space:]]+pam_permit' /etc/pam.d 2>/dev/null | while IFS= read -r l; do
    flag "Suspicious PAM line: $l"
  done

  # SUID files that no package installed
  echo "Checking SUID files against installed packages..."
  while IFS= read -r f; do
    # Ubuntu merged /bin into /usr/bin, so dpkg may know the file by its old /bin path
    alt="$(sed -E 's#^/usr/(s?bin|lib)/#/\1/#' <<<"$f")"
    dpkg -S "$f" >/dev/null 2>&1 || dpkg -S "$alt" >/dev/null 2>&1 \
      || flag "SUID file not from any package: $(ls -l "$f")"
  done < <(find / -xdev -perm -4000 -type f 2>/dev/null)

  # Files in temp dirs that can be executed
  find /tmp /var/tmp /dev/shm -type f -perm -u+x 2>/dev/null | while IFS= read -r f; do
    flag "Executable file in a temp dir: $f"
  done

  # Package files whose contents changed (modified sshd, PAM module, ps, ss, etc.)
  echo "Verifying key package files (dpkg --verify)..."
  dpkg --verify openssh-server openssh-client libpam-modules libpam-modules-bin libpam-runtime \
       passwd login sudo coreutils procps iproute2 util-linux findutils bash \
       postfix dovecot-core dovecot-imapd dovecot-pop3d 2>/dev/null \
  | awk '$1 ~ /^..5/' | while read -r _ a b; do
      if [[ "$a" == c ]]; then
        info "Config file changed from package default (expected if you configured it): $b"
      else
        flag "PACKAGE BINARY MODIFIED (possible trojan): $a"
      fi
    done

  # ------------------------------------------------------------------------
  section "6. SSH"
  if have sshd; then
    if ! err="$(sshd -t 2>&1)"; then
      if [[ "$err" == *"privilege separation directory"* ]]; then
        info "sshd can't self-test because /run/sshd is missing (sshd is stopped). Reading config files instead (approximate)."
      else
        flag "sshd config has errors (sshd -t): $err"
      fi
    fi
    T="$(sshd -T 2>/dev/null)"
    if [[ -z "$T" ]]; then
      # Fallback: first value wins, drop-ins are normally included before the main file
      T="$(cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \
           | grep -vE '^[[:space:]]*(#|$)' | awk '{k=tolower($1)} !(k in seen) {seen[k]=1; $1=k; print}')"
      [[ "$T" == *authorizedkeysfile* ]] || T+=$'\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2'
      [[ "$T" == *permitrootlogin* ]]    || T+=$'\npermitrootlogin prohibit-password'
    fi
    get() { awk -v k="$1" '$1==k {$1=""; sub(/^ /,""); print}' <<<"$T"; }
    for k in permitrootlogin passwordauthentication permitemptypasswords pubkeyauthentication \
             authorizedkeysfile allowusers allowgroups port x11forwarding maxauthtries; do
      info "$k = $(get "$k")"
    done
    [[ "$(get permitrootlogin)" == yes ]] && flag "SSH allows root login with a password (PermitRootLogin yes)"
    [[ "$(get permitemptypasswords)" == yes ]] && flag "SSH allows empty passwords"
    akf="$(get authorizedkeysfile)"
    for f in $akf; do
      [[ "$f" == .ssh/* || "$f" == %h/.ssh/* ]] || flag "AuthorizedKeysFile points somewhere unusual: $f"
    done
    [[ -z "$(get allowusers)$(get allowgroups)" ]] && info "No AllowUsers set - any account with a password/key can SSH in"
    grep -qiE '^[[:space:]]*Include' /etc/ssh/sshd_config || info "sshd_config has no Include line (drop-in files are ignored)"
  else
    info "sshd not installed"
  fi

  # ------------------------------------------------------------------------
  section "7. POSTFIX"
  if have postconf; then
    pc() { postconf -h "$1" 2>/dev/null; }
    info "mail_version = $(pc mail_version)   myhostname = $(pc myhostname)"
    info "inet_interfaces = $(pc inet_interfaces)"

    mn="$(pc mynetworks)"
    info "mynetworks = $mn"
    if [[ "$mn" == *0.0.0.0/0* || "$mn" == *"::/0"* || "$mn" == *"[::]/0"* ]]; then
      flag "mynetworks trusts EVERYONE - this box is an open relay"
    fi

    rr="$(pc smtpd_relay_restrictions)"; rc="$(pc smtpd_recipient_restrictions)"
    info "smtpd_relay_restrictions = $rr"
    info "smtpd_recipient_restrictions = $rc"
    if [[ "$rr $rc" != *reject_unauth_destination* && "$rr $rc" != *defer_unauth_destination* ]]; then
      flag "No reject_unauth_destination in relay/recipient restrictions - likely an OPEN RELAY"
    fi
    first="$(echo "$rr" | tr ',' ' ' | awk '{print $1}')"
    [[ "$first" == permit ]] && flag "smtpd_relay_restrictions starts with a bare 'permit' (allows everything)"

    # Silent copies of mail to an attacker
    for k in always_bcc sender_bcc_maps recipient_bcc_maps; do
      v="$(pc "$k")"
      [[ -n "$v" ]] && flag "$k is set (copies mail somewhere): $v"
    done
    v="$(pc relayhost)";      [[ -n "$v" ]] && flag "relayhost is set (all outbound mail goes through it): $v"
    v="$(pc content_filter)"; [[ -n "$v" ]] && flag "content_filter is set (mail passes through it - legit if it's amavis): $v"
    info "smtpd_milters = $(pc smtpd_milters)   (opendkim/spam filters are normal)"
    for k in virtual_alias_maps transport_maps header_checks body_checks; do
      v="$(pc "$k")"; [[ -n "$v" ]] && info "$k = $v  (review the file it points to)"
    done
    [[ "$(pc disable_vrfy_command)" != yes ]] && flag "disable_vrfy_command is not yes (attackers can test which users exist)"
    info "smtpd_sasl_auth_enable = $(pc smtpd_sasl_auth_enable)   smtpd_tls_security_level = $(pc smtpd_tls_security_level)   smtpd_tls_auth_only = $(pc smtpd_tls_auth_only)"

    echo "Postfix network listeners (master.cf):"
    postconf -M 2>/dev/null | awk '$2=="inet"' | sed 's/^/     /'
    postconf -M 2>/dev/null | grep -E '/tmp/|/dev/shm|bash|sh -c|[[:space:]]nc[[:space:]]|python|perl|user=root' \
      | while IFS= read -r l; do flag "Suspicious master.cf service: $l"; done

    # Aliases that pipe mail into a command = code execution by sending an email
    for f in $( { echo /etc/aliases; pc alias_maps | tr ', ' '\n\n' | sed 's/^[a-z]*://'; } | sort -u); do
      [[ -f "$f" ]] || continue
      grep -nE '^[^#]*(\||:include:)' "$f" 2>/dev/null | while IFS= read -r l; do
        flag "Alias in $f pipes to a command or includes a file: $l"
      done
    done
    if [[ /etc/aliases -nt /etc/aliases.db && -f /etc/aliases.db ]]; then
      info "/etc/aliases is newer than aliases.db (someone edited it without running newaliases, or forgot)"
    fi

    # .forward files can also pipe mail into commands
    find /root /home /var -maxdepth 3 -name .forward -type f 2>/dev/null | while IFS= read -r f; do
      flag ".forward file $f :: $(tr '\n' ' ' <"$f" | cut -c1-120)"
    done

    if have postqueue; then
      q="$(postqueue -p 2>/dev/null | tail -n1)"
      info "Mail queue: $q"
      n="$(grep -oE 'in [0-9]+ Request' <<<"$q" | grep -oE '[0-9]+' || echo 0)"
      (( ${n:-0} > 100 )) && flag "Mail queue has $n messages - possible spam relay"
    fi

    if [[ -f /var/log/mail.log ]]; then
      info "SASL auth failures in mail.log: $(grep -c 'SASL.*authentication failed' /var/log/mail.log 2>/dev/null || true)"
      info "Relay access denied in mail.log: $(grep -c 'Relay access denied' /var/log/mail.log 2>/dev/null || true)"
    fi
    systemctl is-active --quiet postfix && ok "postfix is running" || flag "postfix is NOT running"
  else
    info "Postfix not installed"
  fi

  # ------------------------------------------------------------------------
  section "8. DOVECOT"
  if have doveconf; then
    dc() { doveconf -h "$1" 2>/dev/null; }
    info "version = $(dovecot --version 2>/dev/null)"
    for k in protocols listen ssl auth_mechanisms mail_location; do
      info "$k = $(dc "$k")"
    done
    # Dovecot 2.3 uses disable_plaintext_auth, 2.4 uses auth_allow_cleartext
    v="$(dc disable_plaintext_auth)"; [[ "$v" == no ]] && flag "disable_plaintext_auth = no (passwords can be sent unencrypted)"
    v="$(dc auth_allow_cleartext)";   [[ "$v" == yes ]] && flag "auth_allow_cleartext = yes (passwords can be sent unencrypted)"
    v="$(dc ssl)";                    [[ "$v" == no ]] && flag "Dovecot ssl = no (no TLS for IMAP/POP)"
    v="$(dc auth_debug_passwords)";   [[ "$v" == yes ]] && flag "auth_debug_passwords = yes (passwords written to logs)"
    v="$(dc auth_verbose_passwords)"; [[ -n "$v" && "$v" != no ]] && flag "auth_verbose_passwords = $v (passwords written to logs)"

    # A static or nopassword passdb can let anyone log in as any user
    doveconf -n 2>/dev/null | grep -nE 'nopassword|driver[[:space:]]*=[[:space:]]*static|passdb[[:space:]]+static|args[[:space:]]*=.*password=' \
      | while IFS= read -r l; do flag "Suspicious Dovecot passdb setting: $l"; done
    echo "Dovecot passdb/userdb blocks:"
    doveconf -n 2>/dev/null | grep -A4 -E '^(passdb|userdb)' | sed 's/^/     /'
    systemctl is-active --quiet dovecot && ok "dovecot is running" || flag "dovecot is NOT running"
  else
    info "Dovecot not installed"
  fi

  echo "Mail configs changed in the last 2 days:"
  find /etc/postfix /etc/dovecot /etc/aliases -mtime -2 -type f 2>/dev/null | sed 's/^/     /'

  # ------------------------------------------------------------------------
  section "9. WEB ROOT (webmail)"
  if [[ -d /var/www ]]; then
    # Webshell = takes input from the request AND runs it
    grep -rlE '\$_(GET|POST|REQUEST|COOKIE|SERVER)' --include='*.php' /var/www 2>/dev/null \
      | xargs -r grep -lE '(eval|assert|system|shell_exec|passthru|exec|popen|proc_open)[[:space:]]*\(' 2>/dev/null \
      | xargs -r grep -lE '(eval|assert|system|shell_exec|passthru|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|base64_decode[[:space:]]*\([[:space:]]*\$_' 2>/dev/null \
      | while IFS= read -r f; do flag "Possible webshell (runs request input directly): $f"; done
    find /var/www -name '.*.php' -type f 2>/dev/null | while IFS= read -r f; do
      flag "Hidden PHP file: $f"
    done
    echo "PHP files changed in the last 2 days:"
    find /var/www -name '*.php' -mtime -2 -type f 2>/dev/null | head -n 30 | sed 's/^/     /'
  else
    info "/var/www not present"
  fi

  # ------------------------------------------------------------------------
  section "10. RECENTLY CHANGED FILES (last 24h)"
  find /etc /usr/bin /usr/sbin /usr/local /root /home -xdev -type f -mmin -1440 2>/dev/null \
    | grep -vE '/\.cache/|/\.bash_history$|^/root/audit-' | head -n 60 | sed 's/^/     /'

  # ------------------------------------------------------------------------
  section "APPENDIX: RAW OUTPUT"
  echo "--- ss -tulpn ---";            have ss && ss -tulpn 2>/dev/null
  echo "--- ufw status verbose ---";   have ufw && ufw status verbose 2>/dev/null
  echo "--- iptables -S ---";          have iptables && iptables -S 2>/dev/null
  echo "--- systemctl list-timers ---"; systemctl list-timers --all --no-pager 2>/dev/null
  echo "--- enabled services ---";      systemctl list-unit-files --state=enabled --no-pager 2>/dev/null
  echo "--- ps auxf ---";               ps auxf 2>/dev/null

  # ------------------------------------------------------------------------
  n="$(wc -l <"$FLAGFILE")"
  section "SUMMARY: $n finding(s)"
  if [[ "$n" -eq 0 ]]; then
    echo "Nothing flagged. Still skim the sections above."
  else
    sed 's/^/[!!] /' "$FLAGFILE"
  fi
  echo
  echo "Report saved to $REPORT"
}

main 2>&1 | tee "$REPORT"
