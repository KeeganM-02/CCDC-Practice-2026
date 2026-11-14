#!/bin/bash
# ecom-audit.sh - read-only security and health check for the Rocky Linux
# e-commerce box: nginx in front of a nopCommerce (.NET) store, whose database
# is Microsoft SQL Server on another machine.
#
# It changes NOTHING on the system. It only looks, prints what it finds, and
# saves a log plus a snapshot in /root/audit. Run it again later and the
# "CHANGES SINCE LAST RUN" section shows what is different (new users, new
# ports, new store admins, changed app files...).
#
# Usage:   sudo bash ecom-audit.sh
# Read the [!!] lines in the SUMMARY at the bottom first.

# ---------- Settings: edit these to match the box ----------
APP_DIR=/var/www/nopcommerce              # nopCommerce app folder
APP_SERVICE=""                            # systemd service running the app (blank = find it automatically)
APP_USER=nopcommerce                      # account the app runs as
APP_PORT=5000                             # local port the app listens on (nginx forwards to it)
EXPECTED_LOGIN_USERS="root sysadmin"      # accounts allowed to log in
EXPECTED_ADMINS="sysadmin"                # accounts allowed in wheel (sudo)
EXPECTED_PORTS="80 443 161"               # ports allowed open to the network (161 = SNMP; add 22 if SSH is needed)
EXPECTED_FW_SERVICES="ssh http https snmp dhcpv6-client"
# outgoing connections that are normal for this box, as program:port
EXPECTED_OUTBOUND="dotnet:1433 sssd_be:389 sssd_be:636 sssd_be:88 sssd_be:3268 splunkd:9997 splunkd:8089"
SQLCMD=/opt/mssql-tools18/bin/sqlcmd      # SQL Server command-line tool (optional)
BACKUP_DIR=/root/backups
# The database server, name and login are read from the app's connection string.
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

# find the systemd service that runs the store (whatever owns the app port)
if [ -z "$APP_SERVICE" ] || ! systemctl cat "$APP_SERVICE" >/dev/null 2>&1; then
  pid=$(ss -H -tlnp "sport = :$APP_PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -n 1 | cut -d= -f2)
  [ -n "$pid" ] && APP_SERVICE=$(ps -o unit= -p "$pid" 2>/dev/null | tr -d ' ')
fi

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
info "Local accounts that can log in:"; indent < "$SNAP/login-users.txt"
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
warn_each "Cron job (check it)" < <(grep -v 'backup' "$SNAP/crontabs.txt")

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
info "Services/timers not from any package (the store and Splunk are expected here; anything else, check):"
if [ -s "$SNAP/unowned-units.txt" ]; then indent < "$SNAP/unowned-units.txt"; else echo "     none"; fi
warn_each "Service/timer not from any package (someone added it?)" < <(grep -viE "nopcommerce|${APP_SERVICE:-nopcommerce}|splunk" "$SNAP/unowned-units.txt")

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
  if [ "$port" = "$APP_PORT" ]; then warn "Store app port $APP_PORT is open to the network; it should be localhost only ($proc)"; continue; fi
  in_list "$port" "$EXPECTED_PORTS" || warn "Unexpected open port: $proto $addr ($proc)"
done < "$SNAP/listening.txt"

info "Established connections:"
ss -H -tnp state established 2>/dev/null | awk '{print $3, $4, ($NF ~ /users:/ ? $NF : "unknown-process")}' | sed -E 's/users:\(\("([^"]+)",pid=([0-9]+).*/\1(pid=\2)/' > "$SNAP/.established"
if [ -s "$SNAP/.established" ]; then indent < "$SNAP/.established"; else echo "     none"; fi
warn_each "Unexpected outgoing connection (your browser or dnf is fine; otherwise a reverse shell?)" < <(
  while read -r local peer proc; do
    lport=${local##*:}; phost=${peer%:*}; pport=${peer##*:}
    case "$phost" in 127.*|"[::1]"|::1|"[::ffff:127."*) continue ;; esac
    in_list "$lport" "$listen_ports" && continue
    in_list "${proc%(pid=*}:$pport" "$EXPECTED_OUTBOUND" && continue
    echo "${proc%(pid=*} -> $peer"
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
show "ps -eo pid,user:14,%cpu,%mem,args --sort=-%cpu | head -n 8 | cut -c1-150"
PS=$(ps -eo pid=,user:24=,args= 2>/dev/null)
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
warn_each "Store account running something other than the store (code execution through the site?)" < <(
  awk -v u="$APP_USER" '$2 == u' <<< "$PS" | grep -vE '^[[:space:]]*[0-9]+ +[^ ]+ +[^ ]*dotnet( |$)' | cut -c1-150)
warn_each "nginx account running something other than nginx" < <(
  awk '$2 == "nginx"' <<< "$PS" | grep -vE '^[[:space:]]*[0-9]+ +nginx +nginx: ' | cut -c1-150)

# ==========================================================================
section "WEB (NGINX + NOPCOMMERCE)"
if systemctl is-active --quiet nginx; then ok "nginx is running"; else warn "nginx is NOT running"; fi
if [ -n "$APP_SERVICE" ] && [ "$APP_SERVICE" != "-" ]; then
  if systemctl is-active --quiet "$APP_SERVICE"; then ok "Store app ($APP_SERVICE) is running"; else warn "Store app ($APP_SERVICE) is NOT running"; fi
else
  warn "Could not find the store's service (nothing on port $APP_PORT?). Set APP_SERVICE at the top."
fi
if have nginx; then
  out=$(nginx -t 2>&1)
  if grep -q 'test is successful' <<< "$out"; then ok "nginx config test passed"; else warn "nginx config test failed"; indent <<< "$out"; fi
fi
for url in "http://127.0.0.1:$APP_PORT/" "https://localhost/" "https://localhost/login"; do
  code=$(curl -sk --noproxy '*' -o /dev/null -m 15 -w '%{http_code}' "$url")
  case "$code" in
    200|301|302) ok "$url answers $code" ;;
    *) warn "$url answers ${code:-nothing} (store may be down)" ;;
  esac
done
title=$(curl -skL --noproxy '*' -m 15 https://localhost/ | grep -oiE '<title>[^<]*' | head -n 1 | sed 's/<title>//I')
info "Storefront page title: ${title:-none}"
echo "$title" > "$SNAP/store-title.txt"

if [ -d "$APP_DIR" ]; then
  # folders the store rewrites on its own (thumbnails, bundles, temp uploads)
  EXCL=( -path "$APP_DIR/wwwroot/images/thumbs" -o -path "$APP_DIR/wwwroot/bundles" -o -path "$APP_DIR/App_Data/TempUploads"
         -o -path "$APP_DIR/App_Data/DataProtectionKeys" -o -path "$APP_DIR/App_Data/Logs" -o -path "$APP_DIR/wwwroot/files/exportimport" -o -path "$APP_DIR/logs" )
  warn_each "Code file in an upload folder (web shell?)" < <(find "$APP_DIR/wwwroot/images" "$APP_DIR/wwwroot/files" -type f \
    \( -iname '*.php*' -o -iname '*.asp*' -o -iname '*.ashx' -o -iname '*.cshtml' -o -iname '*.dll' -o -iname '*.exe' -o -iname '*.so' -o -iname '*.sh' -o -iname '*.py' -o -iname '*.pl' -o -iname '*.jsp' \) 2>/dev/null)
  warn_each "Script file a .NET store doesn't use" < <(find "$APP_DIR" \( "${EXCL[@]}" \) -prune -o -type f \( -iname '*.php*' -o -iname '*.jsp' -o -iname '*.sh' -o -iname '*.py' -o -iname '*.pl' \) -print 2>/dev/null)
  warn_each "Store file changed in the last 2 hours (plugins in $APP_DIR/Plugins matter most)" < <(find "$APP_DIR" \( "${EXCL[@]}" \) -prune -o -type f -mmin -120 -print 2>/dev/null)
  warn_each "World-writable file in the store" < <(find "$APP_DIR" -perm -o+w ! -type l 2>/dev/null)
  info "$(find "$APP_DIR" -user "$APP_USER" -name '*.dll' 2>/dev/null | wc -l) store DLLs are owned by $APP_USER (that account can rewrite the store's code)"
  info "$(find "$APP_DIR/Plugins" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l) plugin folders in $APP_DIR/Plugins"
  find "$APP_DIR" \( "${EXCL[@]}" \) -prune -o -type f -print0 2>/dev/null | xargs -0 -r sha256sum \
    | sed -E 's/^([0-9a-f]{16})[0-9a-f]*  (.*)$/\2  \1/' | sort > "$SNAP/store-files.txt"
  info "Fingerprinted $(wc -l < "$SNAP/store-files.txt") store files (next run shows any that change)"
else
  warn "Store folder $APP_DIR not found. Set APP_DIR at the top."
fi
nginx -T 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' > "$SNAP/nginx-config.txt"

AL=/var/log/nginx/access.log; EL=/var/log/nginx/error.log
if [ -f "$AL" ]; then
  info "Top client IPs:"; awk '{print $1}' "$AL" | sort | uniq -c | sort -rn | head -n 5 | indent
  info "Login attempts (POST /login) by IP:"; grep '"POST /login' "$AL" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 5 | indent
  ATTACK_RE='\.\./|%2e%2e|/etc/passwd|union[^a-z]+select|<script|%3cscript|cmd=|/bin/(ba)?sh|\.php|\.aspx?|\.jsp|\.env|\.git/|sqlmap|nikto|nmap|gobuster|dirbuster|wp-login'
  warn_each "Attack-looking request" < <(grep -vE '^(127\.0\.0\.1|::1) ' "$AL" | grep -iE "$ATTACK_RE" | tail -n 10 | cut -c1-170)
fi
[ -f "$EL" ] && { info "Last nginx errors:"; tail -n 6 "$EL" | cut -c1-170 | indent; }
if [ -n "$APP_SERVICE" ] && [ "$APP_SERVICE" != "-" ]; then
  info "Last store app log lines:"; journalctl -u "$APP_SERVICE" -n 6 --no-pager -o cat 2>/dev/null | cut -c1-170 | indent
fi

# ==========================================================================
section "STORE DATABASE (MSSQL)"
CONF=""
for f in "$APP_DIR/App_Data/appsettings.json" "$APP_DIR/App_Data/dataSettings.json"; do
  [ -z "$CONF" ] && grep -qi 'connectionstring' "$f" 2>/dev/null && CONF=$f
done
CS=""
[ -n "$CONF" ] && CS=$(grep -ohiE '"(Data)?ConnectionString"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONF" | head -n 1 | sed -E 's/^[^:]*:[[:space:]]*"//; s/"$//; s/\\\\/\\/g')
# read one setting (by any of its names) out of the connection string
cs_get() {
  tr ';' '\n' <<< "$CS" | awk -v keys="$1" 'BEGIN { n = split(keys, k, "|") }
    { key = $0; sub(/=.*/, "", key); gsub(/^[ \t]+|[ \t]+$/, "", key)
      for (i = 1; i <= n; i++) if (tolower(key) == k[i]) { val = $0; sub(/^[^=]*=/, "", val); gsub(/^[ \t]+|[ \t]+$/, "", val); print val; exit } }'
}
if [ -z "$CS" ]; then
  warn "Could not find the store's connection string in $APP_DIR/App_Data"
else
  info "Connection string is in $CONF ($(stat -c '%A %U:%G' "$CONF"))"
  [ -n "$(find "$CONF" -perm -o+r 2>/dev/null)" ] && warn "$CONF holds the database password and every account can read it"
  DB_SRV=$(cs_get "data source|server|address|addr|network address")
  DB_DB=$(cs_get "initial catalog|database")
  DB_USR=$(cs_get "user id|uid|user|username")
  DB_PW=$(cs_get "password|pwd")
  DB_INTEG=$(cs_get "integrated security|trusted_connection")
  host=${DB_SRV#tcp:}; host=${host%%,*}; host=${host%%\\*}
  port=1433; case "$DB_SRV" in *,*) port=${DB_SRV##*,} ;; esac
  info "Database server: $DB_SRV ($(getent hosts "$host" | awk '{print $1}' | head -n 1))   database: ${DB_DB:-?}   login: ${DB_USR:-?}"
  printf '%s %s %s\n' "$DB_SRV" "$DB_DB" "$DB_USR" > "$SNAP/db-connection.txt"
  [ "${DB_USR,,}" = "sa" ] && warn "The store logs in to SQL Server as 'sa' (full control of the whole SQL server)"
  if timeout 4 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then ok "Database server $host:$port is reachable"
  else warn "Cannot reach the database server $host:$port (the store will break)"; fi

  if [ ! -x "$SQLCMD" ]; then
    info "sqlcmd not installed, so store admins and data are not checked. To enable:"
    info "  sudo curl -o /etc/yum.repos.d/mssql-release.repo https://packages.microsoft.com/config/rhel/9/prod.repo"
    info "  sudo ACCEPT_EULA=Y dnf install -y mssql-tools18"
  elif [ -n "$DB_INTEG" ] && [ "${DB_INTEG,,}" != "false" ]; then
    info "The store uses Windows login to SQL Server, so store data can't be checked from here"
  else
    mq() { SQLCMDPASSWORD="$DB_PW" "$SQLCMD" -S "$DB_SRV" -U "$DB_USR" -d "$DB_DB" -C -l 5 -W -h -1 -s '|' -Q "SET NOCOUNT ON; $1" 2>&1; }
    test_out=$(mq "SELECT 1" | tr -d '[:space:]')
    if [ "$test_out" != 1 ]; then
      warn "Could not query the store database with the store's login: $(mq "SELECT 1" | head -n 1 | cut -c1-120)"
    else
      ok "Logged in to the store database as $DB_USR"
      [ "$(mq "SELECT IS_SRVROLEMEMBER('sysadmin')" | tr -d '[:space:]')" = 1 ] && warn "The store's SQL login is a sysadmin on the SQL server (it only needs its own database)"
      mq "SELECT c.Id, ISNULL(c.Username,''), ISNULL(c.Email,''), CASE c.Active WHEN 1 THEN 'active' ELSE 'disabled' END FROM Customer c JOIN Customer_CustomerRole_Mapping m ON m.Customer_Id = c.Id JOIN CustomerRole r ON r.Id = m.CustomerRole_Id WHERE r.SystemName = 'Administrators' AND c.Deleted = 0 ORDER BY c.Id" > "$SNAP/store-admins.txt"
      info "Store admin accounts (id | username | email | status):"; indent < "$SNAP/store-admins.txt"
      [ "$(grep -c . "$SNAP/store-admins.txt")" -gt 1 ] && warn "There are $(grep -c . "$SNAP/store-admins.txt") store admin accounts; make sure you know every one"
      IFS='|' read -r np no nc < <(mq "SELECT (SELECT COUNT(*) FROM Product WHERE Deleted = 0), (SELECT COUNT(*) FROM [Order] WHERE Deleted = 0), (SELECT COUNT(*) FROM Customer WHERE Deleted = 0 AND Email IS NOT NULL)")
      info "Store data: ${np:-?} products, ${no:-?} orders, ${nc:-?} registered customers"
      echo "${np:-} ${no:-} ${nc:-}" > "$SNAP/store-counts.dat"
      if [ -n "$PREV" ] && [ -s "$PREV/store-counts.dat" ]; then
        read -r pnp pno _ < "$PREV/store-counts.dat"
        [ -n "$np" ] && [ -n "$pnp" ] && [ "$np" -lt "$pnp" ] 2>/dev/null && warn "Products dropped from $pnp to $np since last run"
        [ -n "$no" ] && [ -n "$pno" ] && [ "$no" -lt "$pno" ] 2>/dev/null && warn "Orders dropped from $pno to $no since last run"
      fi
    fi
  fi
fi
unset DB_PW

# ==========================================================================
section "SNMP, LOGGING AND DOMAIN"
SNMPCONF=/etc/snmp/snmpd.conf
if systemctl is-active --quiet snmpd; then ok "snmpd is running"; else warn "snmpd is NOT running"; fi
if [ -f "$SNMPCONF" ]; then
  grep -vE '^[[:space:]]*(#|$)' "$SNMPCONF" > "$SNAP/snmpd-config.txt"
  warn_each "SNMP uses a default community name" < <(grep -iwE 'public|private' "$SNAP/snmpd-config.txt")
  warn_each "SNMP allows changes (should be read-only)" < <(grep -iE '^[[:space:]]*(rwcommunity|rwuser)' "$SNAP/snmpd-config.txt"; awk '$1 == "access" && $8 != "none"' "$SNAP/snmpd-config.txt")
fi
if pgrep -x splunkd >/dev/null; then ok "Splunk forwarder is running"
elif [ -d /opt/splunkforwarder ]; then warn "Splunk forwarder is installed but NOT running (logs aren't being sent)"; fi
if systemctl cat sssd >/dev/null 2>&1; then
  if systemctl is-active --quiet sssd; then ok "sssd (domain logins) is running"; else warn "sssd is NOT running (domain users can't log in)"; fi
  have realm && realm list 2>/dev/null | grep -E 'domain-name|login-policy|permitted-' | indent
fi

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
  warn_each "System program was modified" < <(rpm -V coreutils procps-ng iproute openssh-server openssh-clients sudo shadow-utils util-linux passwd bash findutils grep sed gawk nginx net-snmp 2>/dev/null | awk '$1 ~ /5/ && $2 != "c" {print $NF}')
fi
warn_each "Suspicious file in a temp folder" < <(find /tmp /var/tmp /dev/shm -xdev -type f ! -name '.X*-lock' \( -perm -u+x -o -name '.*' -o -iname '*.sh' -o -iname '*.php' -o -iname '*.py' -o -iname '*.pl' \) 2>/dev/null)

# ==========================================================================
section "BACKUPS"
latest=""
for d in "$BACKUP_DIR"/*/; do [ -d "$d" ] && latest=${d%/}; done
if [ -z "$latest" ]; then
  warn "No backups found in $BACKUP_DIR"
else
  age=$(( ($(date +%s) - $(stat -c %Y "$latest")) / 60 ))
  info "Newest backup: $latest ($age minutes old)"
  [ "$age" -gt 120 ] && warn "Newest backup is over 2 hours old"
  if [ -f "$latest/SHA256SUMS" ]; then
    if (cd "$latest" && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1); then ok "Newest backup passes its checksum check"
    else warn "Newest backup FAILS its checksum check (tampered or damaged)"; fi
  fi
fi

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
