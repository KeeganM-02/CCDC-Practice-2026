#!/bin/bash
# ecom-audit.sh - read-only security and health check for the Rocky Linux
# e-commerce box (Apache + PHP-FPM + MariaDB + OpenCart).
#
# It changes NOTHING on the system. It only looks, prints what it finds, and
# saves a log plus a snapshot in /root/audit. Run it again later and the
# "CHANGES SINCE LAST RUN" section shows what is different (new users, new
# ports, edited website files, new admins...).
#
# Usage:   sudo bash ecom-audit.sh
# Read the [!!] lines in the SUMMARY at the bottom first.

# ---------- Settings: edit these to match the box ----------
WEBROOT=/var/www/html
DB_NAME=opencart
DB_PREFIX=oc_
EXPECTED_LOGIN_USERS="root ecomuser"            # accounts allowed to log in
EXPECTED_ADMINS="ecomuser"                      # accounts allowed in wheel (sudo)
EXPECTED_PORTS="22 80 443 68 546"               # ports allowed open to the network
EXPECTED_FW_SERVICES="ssh http https dhcpv6-client"
EXPECTED_DB_USERS="root ocuser bkpuser mysql mariadb.sys"
# ------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then echo "Run as root: sudo bash $0"; exit 1; fi

if [ -t 1 ]; then RED=$'\e[1;31m'; GRN=$'\e[32m'; BLU=$'\e[1;36m'; DIM=$'\e[2m'; NC=$'\e[0m'
else RED=''; GRN=''; BLU=''; DIM=''; NC=''; fi

umask 077
OUT=/root/audit
TS=$(date +%F_%H%M%S)
LOG="$OUT/audit-$TS.log"
SNAP="$OUT/snap-$TS"
PREV=""
for d in "$OUT"/snap-*; do [ -d "$d" ] && PREV=$d; done
mkdir -p "$SNAP"

exec > >(tee "$LOG") 2>&1
TEE_PID=$!

WARNS=()
SECTION=""
section() { SECTION=$1; printf '\n%s==================== %s ====================%s\n' "$BLU" "$1" "$NC"; }
warn()    { WARNS+=("[$SECTION] $*"); printf '%s[!!] %s%s\n' "$RED" "$*" "$NC"; }
ok()      { printf '%s[ok] %s%s\n' "$GRN" "$*" "$NC"; }
info()    { printf '[..] %s\n' "$*"; }
indent()  { sed 's/^/     /'; }
have()    { command -v "$1" >/dev/null 2>&1; }
show()    { printf '%s$ %s%s\n' "$DIM" "$1" "$NC"; bash -c "$1" 2>&1 | indent; }
in_list() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }
# warn once per input line (max 15), e.g.  warn_each "message" < <(command)
warn_each() {
  local n=0 line
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$((n + 1)); [ "$n" -le 15 ] && warn "$1: $line"
  done
  [ "$n" -gt 15 ] && warn "$1: ...and $((n - 15)) more"
}
# print the files (from the arguments) that no installed package owns
unowned() {
  have rpm || return 0
  [ $# -eq 0 ] && return 0
  rpm -qf -- "$@" 2>&1 | sed -n 's/^file \(.*\) is not owned by any package$/\1/p'
}
# commands attackers use for reverse shells, droppers and miners
SUSP_RE='/dev/(tcp|udp)/|\b(nc|ncat|netcat|socat|xmrig|chisel)\b|\b(ba)?sh -i\b|mkfifo|python[0-9.]* -c|perl -e|php -r|base64 -d|(curl|wget)[^|]*\|[[:space:]]*(ba)?sh'

printf '%sE-commerce box audit (read-only) | %s | %s%s\n' "$BLU" "$(hostname)" "$(date '+%F %T')" "$NC"
info "Takes about 30 seconds."

# ==========================================================================
section "SYSTEM"
info "OS: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")   Up: $(uptime -p 2>/dev/null)   Load: $(cut -d' ' -f1-3 /proc/loadavg)"
show "ip -br addr"
show "who"
show "last -a -n 10 | head -n 10"
have lastb && show "lastb -a -n 8 2>/dev/null | head -n 8"
while read -r use mnt; do
  [ "${use%\%}" -ge 90 ] 2>/dev/null && warn "Disk $mnt is $use full"
done < <(df -P / /var /tmp 2>/dev/null | awk 'NR > 1 {print $5, $6}' | sort -u)

# ==========================================================================
section "USERS AND SUDO"
awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1" (uid "$3", "$7")"}' /etc/passwd | sort > "$SNAP/login-users.txt"
info "Accounts that can log in:"; indent < "$SNAP/login-users.txt"
while read -r u _; do
  in_list "$u" "$EXPECTED_LOGIN_USERS" || warn "Unexpected account that can log in: $u"
done < "$SNAP/login-users.txt"
warn_each "Extra UID 0 (root-level) account" < <(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
warn_each "Two accounts share UID" < <(cut -d: -f3 /etc/passwd | sort | uniq -d)
warn_each "Account with NO password" < <(awk -F: '$2 == "" {print $1}' /etc/shadow)

wheel=$(getent group wheel | cut -d: -f4)
info "wheel (sudo) members: ${wheel:-none}"
tr ',' '\n' <<< "$wheel" | sort > "$SNAP/wheel.txt"
for u in ${wheel//,/ }; do in_list "$u" "$EXPECTED_ADMINS" || warn "Unexpected sudo (wheel) member: $u"; done

grep -hvE '^[[:space:]]*(#|$)|^[[:space:]]*Defaults' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sort > "$SNAP/sudoers.txt"
info "Active sudo rules:"; indent < "$SNAP/sudoers.txt"
warn_each "Passwordless sudo rule" < <(grep -i 'NOPASSWD' "$SNAP/sudoers.txt")
warn_each "Extra sudo rule" < <(awk '$1 != "root" && $1 != "%wheel" && $1 !~ /_Alias$/ && $1 !~ /^@?include/' "$SNAP/sudoers.txt")
warn_each "File in /etc/sudoers.d (check it)" < <(find /etc/sudoers.d -type f 2>/dev/null)

: > "$SNAP/ssh-keys.txt"
while IFS=: read -r user _ _ _ _ home _; do
  for k in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    [ -s "$k" ] && grep -vE '^[[:space:]]*(#|$)' "$k" | awk -v u="$user" '{print u": "$1" ... "$NF}' >> "$SNAP/ssh-keys.txt"
  done
done < /etc/passwd
warn_each "SSH key can log in as" < "$SNAP/ssh-keys.txt"
info "Last edited: passwd $(date -r /etc/passwd '+%F %R'), shadow $(date -r /etc/shadow '+%F %R'), sudoers $(date -r /etc/sudoers '+%F %R')"

# ==========================================================================
section "SCHEDULED TASKS AND STARTUP"
: > "$SNAP/crontabs.txt"
for f in /var/spool/cron/*; do
  [ -f "$f" ] && grep -vE '^[[:space:]]*(#|$)' "$f" | sed "s|^|crontab of $(basename "$f"): |" >> "$SNAP/crontabs.txt"
done
grep -vE '^[[:space:]]*(#|$)|^[A-Z_]+=' /etc/crontab 2>/dev/null | sed 's|^|/etc/crontab: |' >> "$SNAP/crontabs.txt"
info "Cron jobs:"; if [ -s "$SNAP/crontabs.txt" ]; then indent < "$SNAP/crontabs.txt"; else echo "     none"; fi
warn_each "Cron job (check it)" < <(grep -v '/root/bin/backup.sh' "$SNAP/crontabs.txt")

mapfile -t cronfiles < <(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f 2>/dev/null)
printf '%s\n' "${cronfiles[@]}" | sort > "$SNAP/cron-files.txt"
warn_each "Cron file not from any package (someone added it)" < <(unowned "${cronfiles[@]}")
warn_each "Suspicious cron line" < <(grep -HE "$SUSP_RE" "${cronfiles[@]}" /etc/crontab /dev/null 2>/dev/null | cut -c1-150)
if have atq && [ -n "$(atq 2>/dev/null)" ]; then warn "One-time 'at' jobs are queued"; show "atq"; fi

show "systemctl list-timers --all --no-pager | head -n 20"
systemctl list-unit-files --state=enabled --no-pager --no-legend 2>/dev/null | awk '{print $1}' | sort > "$SNAP/enabled-services.txt"
info "Enabled at boot:"; paste -sd' ' "$SNAP/enabled-services.txt" | fold -s -w 100 | indent
mapfile -t units < <(find /etc/systemd/system /usr/lib/systemd/system /usr/local/lib/systemd/system /run/systemd/system -maxdepth 2 -type f \
  \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -path '*.d/*.conf' \) 2>/dev/null)
unowned "${units[@]}" | sort > "$SNAP/unowned-units.txt"
warn_each "Service/timer not from any package (someone added it)" < "$SNAP/unowned-units.txt"

if [ -x /etc/rc.d/rc.local ] && grep -vE '^[[:space:]]*(#|$)|^touch /var/lock/subsys/local' /etc/rc.d/rc.local | grep -q .; then
  warn "rc.local runs commands at boot"; show "grep -vE '^[[:space:]]*(#|$)' /etc/rc.d/rc.local"
fi
if [ -s /etc/ld.so.preload ]; then warn "/etc/ld.so.preload is set (common rootkit trick)"; show "cat /etc/ld.so.preload"; fi
mapfile -t prof < <(find /etc/profile.d -type f 2>/dev/null)
warn_each "Login script not from any package" < <(unowned "${prof[@]}")
have rpm && warn_each "System file edited" < <(rpm -V setup bash 2>/dev/null | awk '$1 ~ /5/ {print $NF}' | grep -E '^/etc/(bashrc|profile|environment|hosts)$')
warn_each "Suspicious line in a login file" < <(grep -HnE "$SUSP_RE|alias (sudo|su|ps|ss|netstat|cat|systemctl)=" /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc /home/*/.bash_profile /etc/bashrc /etc/profile 2>/dev/null)

# ==========================================================================
section "NETWORK AND FIREWALL"
show "ss -tulpn"
ss -H -tulpn 2>/dev/null | awk '{print $1, $5, ($NF ~ /users:/ ? $NF : "unknown-process")}' | sed -E 's/users:\(\("([^"]+)".*/\1/' | sort -u > "$SNAP/listening.txt"
listen_ports=" "
while read -r proto addr proc; do
  port=${addr##*:}; host=${addr%:*}
  listen_ports+="$port "
  case "$host" in 127.*|"[::1]"|::1|*%lo) continue ;; esac
  if [ "$port" = 3306 ]; then warn "MariaDB (3306) is open to the network; it should be localhost only ($proc)"; continue; fi
  in_list "$port" "$EXPECTED_PORTS" || warn "Unexpected open port: $proto $addr ($proc)"
done < "$SNAP/listening.txt"

info "Established connections:"
ss -H -tnp state established 2>/dev/null | awk '{print $3, $4, ($NF ~ /users:/ ? $NF : "unknown-process")}' | sed -E 's/users:\(\("([^"]+)",pid=([0-9]+).*/\1(pid=\2)/' > "$SNAP/.established"
if [ -s "$SNAP/.established" ]; then indent < "$SNAP/.established"; else echo "     none"; fi
warn_each "Outgoing connection (fine if it's your browser or dnf; otherwise a reverse shell?)" < <(
  while read -r local peer proc; do
    lport=${local##*:}; phost=${peer%:*}
    case "$phost" in 127.*|"[::1]"|::1|"[::ffff:127."*) continue ;; esac
    in_list "$lport" "$listen_ports" || echo "${proc%(pid=*} -> $peer"
  done < "$SNAP/.established" | sort -u)
rm -f "$SNAP/.established"

if have firewall-cmd; then
  if [ "$(firewall-cmd --state 2>&1)" = running ]; then
    ok "firewalld is running"
    firewall-cmd --list-all > "$SNAP/firewall.txt" 2>&1
    info "Active zones: $(firewall-cmd --get-active-zones 2>/dev/null | grep -v '^ ' | paste -sd' ')"
    indent < "$SNAP/firewall.txt"
    for s in $(firewall-cmd --list-services 2>/dev/null); do in_list "$s" "$EXPECTED_FW_SERVICES" || warn "Firewall allows extra service: $s"; done
    for p in $(firewall-cmd --list-ports 2>/dev/null); do warn "Firewall opens extra port: $p"; done
  else
    warn "firewalld is NOT running"
  fi
else
  warn "firewall-cmd not found"
fi

# ==========================================================================
section "PROCESSES"
show "ps -eo pid,user,%cpu,%mem,args --sort=-%cpu | head -n 8 | cut -c1-150"
PS=$(ps -eo pid=,user=,args= 2>/dev/null)
tmp_procs=""; deleted_procs=""
for p in /proc/[0-9]*; do
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  pid=${p#/proc/}
  case "$exe" in
    *" (deleted)") deleted_procs+="${exe% (deleted)}"$'\n' ;;
    /tmp/*|/var/tmp/*|/dev/shm/*|*/.*/*) tmp_procs+="pid $pid $exe: $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-100)"$'\n' ;;
  esac
done
warn_each "Program running from a temp or hidden folder" <<< "$tmp_procs"
warn_each "Program running from a deleted file (normal right after updates, otherwise suspicious)" < <(sort -u <<< "$deleted_procs")
warn_each "Suspicious command running" < <(grep -E "$SUSP_RE" <<< "$PS" | grep -v 'ecom-audit' | cut -c1-150)
warn_each "Web server account running a non-web program (web shell?)" < <(awk '$2 == "apache"' <<< "$PS" | grep -vE '^[[:space:]]*[0-9]+ +apache +(/usr/sbin/httpd|php-fpm)' | cut -c1-150)

# ==========================================================================
section "WEB SERVER AND OPENCART"
for s in httpd php-fpm; do
  if systemctl is-active --quiet "$s"; then ok "$s is running"; else warn "$s is NOT running"; fi
done
if have httpd; then
  out=$(httpd -t 2>&1)
  if grep -q 'Syntax OK' <<< "$out"; then ok "Apache config syntax OK"; else warn "Apache config test failed"; indent <<< "$out"; fi
fi
for path in / /admin/; do
  code=$(curl -s --noproxy '*' -o /dev/null -m 5 -w '%{http_code}' "http://localhost$path")
  case "$code" in
    200|301|302) ok "http://localhost$path answers $code" ;;
    *) warn "http://localhost$path answers ${code:-nothing} (store may be down)" ;;
  esac
done
title=$(curl -s --noproxy '*' -m 5 http://localhost/ | grep -oiE '<title>[^<]*' | head -n 1 | sed 's/<title>//I')
info "Storefront page title: ${title:-none}"
echo "$title" > "$SNAP/store-title.txt"

[ -d "$WEBROOT/install" ] && warn "$WEBROOT/install still exists (delete it)"
warn_each "PHP file in an image/upload folder (web shell?)" < <(find "$WEBROOT/image" "$WEBROOT/system/storage/upload" "$WEBROOT/system/storage/download" -type f -iname '*.ph*' 2>/dev/null)
WS_RE='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(GET|POST|REQUEST|COOKIE))|(system|shell_exec|passthru|popen|proc_open|assert|exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)|`[[:space:]]*\$_(GET|POST|REQUEST|COOKIE)'
warn_each "Possible web shell" < <(grep -rlE --include='*.ph*' "$WS_RE" "$WEBROOT" 2>/dev/null)

EXCL=( -path "$WEBROOT/system/storage/cache" -o -path "$WEBROOT/system/storage/session"
       -o -path "$WEBROOT/system/storage/logs" -o -path "$WEBROOT/image/cache" )
warn_each "Website file changed in the last 2 hours" < <(find "$WEBROOT" \( "${EXCL[@]}" \) -prune -o -type f -mmin -120 -print 2>/dev/null)
warn_each "World-writable file in the website" < <(find "$WEBROOT" -perm -o+w ! -type l 2>/dev/null)
warn_each "Web server account can edit site code" < <(find "$WEBROOT" \( -path "$WEBROOT/image" -o -path "$WEBROOT/system/storage" \) -prune -o -user apache ! -name config.php -print 2>/dev/null)
for f in "$WEBROOT/config.php" "$WEBROOT/admin/config.php"; do [ -f "$f" ] && info "$(stat -c '%A %U:%G' "$f") $f"; done
find "$WEBROOT" \( "${EXCL[@]}" \) -prune -o -type f -print0 2>/dev/null | xargs -0 -r sha256sum \
  | sed -E 's/^([0-9a-f]{16})[0-9a-f]*  (.*)$/\2  \1/' | sort > "$SNAP/website-files.txt"
info "Fingerprinted $(wc -l < "$SNAP/website-files.txt") website files (next run shows any that change)"

AL=/var/log/httpd/access_log; EL=/var/log/httpd/error_log
if [ -f "$AL" ]; then
  info "Top client IPs:"; awk '{print $1}' "$AL" | sort | uniq -c | sort -rn | head -n 5 | indent
  ATTACK_RE='\.\./|%2e%2e|/etc/passwd|union[^a-z]+select|<script|%3cscript|cmd=|base64_decode|phpinfo|/bin/(ba)?sh|sqlmap|nikto|nmap|gobuster|dirbuster|wp-login'
  warn_each "Attack-looking request" < <(grep -vE '^(127\.0\.0\.1|::1) ' "$AL" | grep -iE "$ATTACK_RE" | tail -n 10 | cut -c1-170)
  warn_each "POST to an unusual PHP file (web shell use?)" < <(grep '"POST ' "$AL" | grep -vE '"POST /(admin/)?index\.php[?" ]' | tail -n 10 | cut -c1-170)
fi
[ -f "$EL" ] && { info "Last Apache errors:"; tail -n 6 "$EL" | cut -c1-170 | indent; }
OCLOG="$WEBROOT/system/storage/logs/error.log"
[ -s "$OCLOG" ] && { info "Last OpenCart errors:"; tail -n 5 "$OCLOG" | cut -c1-170 | indent; }

# ==========================================================================
section "DATABASE (MARIADB)"
if systemctl is-active --quiet mariadb; then ok "mariadb is running"; else warn "mariadb is NOT running"; fi
DBMODE=""
if [ -r /root/.backup.cnf ] && mysql --defaults-extra-file=/root/.backup.cnf --connect-timeout=5 -e 'SELECT 1' >/dev/null 2>&1; then
  DBMODE=cnf
elif mysql --connect-timeout=5 -e 'SELECT 1' >/dev/null 2>&1; then
  DBMODE=socket
elif [ -t 0 ]; then
  read -rsp "MariaDB root password (press Enter to skip database checks): " MYSQL_PWD; echo
  export MYSQL_PWD
  [ -n "$MYSQL_PWD" ] && mysql -u root --connect-timeout=5 -e 'SELECT 1' >/dev/null 2>&1 && DBMODE="pwd"
fi
q() {
  case "$DBMODE" in
    cnf)    mysql --defaults-extra-file=/root/.backup.cnf -N -B --connect-timeout=5 -e "$1" ;;
    socket) mysql -N -B --connect-timeout=5 -e "$1" ;;
    pwd)    mysql -u root -N -B --connect-timeout=5 -e "$1" ;;
  esac 2>/dev/null
}
if [ -z "$DBMODE" ]; then
  warn "Could not log in to MariaDB, database checks skipped"
else
  q "SELECT CONCAT(user,'@',host) FROM mysql.user ORDER BY 1" > "$SNAP/db-users.txt"
  info "Database accounts:"; indent < "$SNAP/db-users.txt"
  while IFS='@' read -r u h; do
    if [ -z "$u" ]; then warn "Anonymous database account @$h"; continue; fi
    in_list "$u" "$EXPECTED_DB_USERS" || warn "Unexpected database account: $u@$h"
    case "$h" in localhost|127.0.0.1|::1) ;; *) warn "Database account allowed from the network: $u@$h" ;; esac
  done < "$SNAP/db-users.txt"
  warn_each "Database account with admin-level privileges" < <(q "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE (Super_priv='Y' OR Grant_priv='Y' OR File_priv='Y' OR Create_user_priv='Y') AND user NOT IN ('root','mariadb.sys','mysql')")
  q "SHOW GRANTS FOR 'ocuser'@'localhost'" > "$SNAP/ocuser-grants.txt"
  info "ocuser permissions:"; indent < "$SNAP/ocuser-grants.txt"
  warn_each "ocuser has rights beyond the store database" < <(grep 'ON \*\.\*' "$SNAP/ocuser-grants.txt" | grep -v 'GRANT USAGE')

  q "SELECT CONCAT(username,' | ',email,' | status ',status,' | added ',date_added) FROM \`$DB_NAME\`.\`${DB_PREFIX}user\` ORDER BY user_id" > "$SNAP/opencart-admins.txt"
  info "OpenCart admin users:"; indent < "$SNAP/opencart-admins.txt"
  read -r np no nc < <(q "SELECT (SELECT COUNT(*) FROM \`$DB_NAME\`.\`${DB_PREFIX}product\`), (SELECT COUNT(*) FROM \`$DB_NAME\`.\`${DB_PREFIX}order\`), (SELECT COUNT(*) FROM \`$DB_NAME\`.\`${DB_PREFIX}customer\`)")
  info "Store data: ${np:-?} products, ${no:-?} orders, ${nc:-?} customers"
  echo "${np:-} ${no:-} ${nc:-}" > "$SNAP/store-counts.dat"
  if [ -n "$PREV" ] && [ -s "$PREV/store-counts.dat" ]; then
    read -r pnp pno _ < "$PREV/store-counts.dat"
    [ -n "$np" ] && [ -n "$pnp" ] && [ "$np" -lt "$pnp" ] && warn "Products dropped from $pnp to $np since last run"
    [ -n "$no" ] && [ -n "$pno" ] && [ "$no" -lt "$pno" ] && warn "Orders dropped from $pno to $no since last run"
  fi
fi
unset MYSQL_PWD
[ -f /var/log/mariadb/mariadb.log ] && { info "Last MariaDB log lines:"; tail -n 4 /var/log/mariadb/mariadb.log | cut -c1-170 | indent; }

# ==========================================================================
section "SELINUX, SSH AND LOGINS"
if have getenforce; then
  m=$(getenforce)
  if [ "$m" = Enforcing ]; then ok "SELinux is Enforcing"; else warn "SELinux is $m (should be Enforcing)"; fi
fi
if have sshd; then
  sshcfg=$(sshd -T 2>/dev/null)
  grep -E '^(port|permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication) ' <<< "$sshcfg" | indent
  grep -qx 'permitrootlogin yes' <<< "$sshcfg" && warn "SSH allows root to log in with a password"
  grep -qx 'permitemptypasswords yes' <<< "$sshcfg" && warn "SSH allows empty passwords"
fi
SEC=/var/log/secure
if [ -f "$SEC" ]; then
  info "Failed logins by IP:"; grep -E 'Failed password|Invalid user' "$SEC" | grep -oE 'from [0-9a-fA-F.:]+' | sort | uniq -c | sort -rn | head -n 5 | indent
  info "Recent successful logins:"; grep 'Accepted ' "$SEC" | tail -n 5 | cut -c1-150 | indent
  info "Recent sudo commands:"; grep 'COMMAND=' "$SEC" | tail -n 8 | sed -E 's/.*sudo\[[0-9]+\]: *//' | cut -c1-150 | indent
  warn_each "Account change in the login log" < <(grep -E "new user|new group|delete user|add '[^']+' to group" "$SEC" | tail -n 10 | cut -c1-150)
fi

# ==========================================================================
section "SYSTEM FILES"
mapfile -t suid < <(find / /home /var /tmp -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort -u)
printf '%s\n' "${suid[@]}" > "$SNAP/suid-files.txt"
info "$(wc -l < "$SNAP/suid-files.txt") SUID/SGID programs found"
warn_each "SUID/SGID program not from any package (root backdoor?)" < <(unowned "${suid[@]}")
if have rpm; then
  info "Checking core programs against their packages..."
  warn_each "System program was modified" < <(rpm -V coreutils procps-ng iproute openssh-server openssh-clients sudo shadow-utils util-linux passwd bash findutils grep sed gawk httpd mariadb-server php-fpm 2>/dev/null | awk '$1 ~ /5/ && $2 != "c" {print $NF}')
fi
warn_each "Suspicious file in a temp folder" < <(find /tmp /var/tmp /dev/shm -xdev -type f ! -name '.X*-lock' \( -perm -u+x -o -name '.*' -o -iname '*.sh' -o -iname '*.php' -o -iname '*.py' -o -iname '*.pl' \) 2>/dev/null)

# ==========================================================================
section "BACKUPS"
latest=""
for d in /root/backups/*/; do [ -d "$d" ] && latest=${d%/}; done
if [ -z "$latest" ]; then
  warn "No backups found in /root/backups"
else
  age=$(( ($(date +%s) - $(stat -c %Y "$latest")) / 60 ))
  info "Newest backup: $latest ($age minutes old)"
  [ "$age" -gt 120 ] && warn "Newest backup is over 2 hours old"
  if [ -f "$latest/SHA256SUMS" ]; then
    if (cd "$latest" && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1); then ok "Newest backup passes its checksum check"
    else warn "Newest backup FAILS its checksum check (tampered or damaged)"; fi
  else
    warn "Newest backup has no SHA256SUMS file"
  fi
fi
if crontab -l 2>/dev/null | grep -q 'backup.sh'; then ok "Automatic backup is scheduled"; else warn "No automatic backup in root's crontab"; fi

# ==========================================================================
section "CHANGES SINCE LAST RUN"
if [ -z "$PREV" ]; then
  info "First run, nothing to compare yet. Run this again later to see what changed."
else
  info "Comparing with $(basename "$PREV")"
  changed=0
  for f in "$SNAP"/*.txt; do
    name=$(basename "$f" .txt)
    [ -f "$PREV/$name.txt" ] || continue
    d=$(diff "$PREV/$name.txt" "$f" | grep -E '^[<>]' | sed -e 's/^</  removed:/' -e 's/^>/  added:  /')
    if [ -n "$d" ]; then
      changed=1
      warn "$name changed since last run ($(wc -l <<< "$d") lines)"
      head -n 30 <<< "$d" | cut -c1-170
    fi
  done
  [ "$changed" -eq 0 ] && ok "Nothing changed since the last run"
fi

# ==========================================================================
section "SUMMARY"
if [ "${#WARNS[@]}" -eq 0 ]; then
  ok "No warnings"
else
  printf '%s%d things to check:%s\n' "$RED" "${#WARNS[@]}" "$NC"
  for w in "${WARNS[@]}"; do printf '%s[!!]%s %s\n' "$RED" "$NC" "$w"; done
fi
info "Full log: $LOG"
info "Snapshot: $SNAP (the next run compares against it)"
info "Finished in $SECONDS seconds"

exec >/dev/null 2>&1
wait "$TEE_PID" 2>/dev/null
while kill -0 "$TEE_PID" 2>/dev/null; do sleep 0.1; done
sed -i 's/\x1b\[[0-9;]*m//g' "$LOG"