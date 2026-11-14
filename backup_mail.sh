#!/usr/bin/env bash
# backup_mail.sh - CCDC backup for the Ubuntu mail server (Postfix + Dovecot)
# Usage: sudo ./backup_mail.sh [-d DIR] [-r USER@HOST:PATH] [-n]
#   -d DIR   where to store backups (default: /root/bak)
#   -r DEST  also copy the backup off the box with scp (e.g. blue@10.0.0.5:~/bak/)
#   -n       configs only, skip mailboxes (fast, for re-running after changes)
#
# What it saves:
#   1. Text snapshots of the *effective* config (postconf -n, doveconf -n),
#      ports, packages and the mail queue -> easy to diff later
#   2. Postfix, Dovecot, aliases, OpenDKIM, Roundcube and web server configs
#   3. Account files (passwd/shadow/group) so mail users can be restored
#   4. The TLS certs and keys Postfix and Dovecot actually point to
#   5. Mailboxes (wherever Dovecot says they live, plus the usual spots)
#   6. SHA256 hashes of everything + a RESTORE.txt cheat sheet

set -uo pipefail

BAK_ROOT="/root/bak"
REMOTE=""
SKIP_MAIL=0

usage() { sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while getopts "d:r:nh" opt; do
  case "$opt" in
    d) BAK_ROOT="$OPTARG" ;;
    r) REMOTE="$OPTARG" ;;
    n) SKIP_MAIL=1 ;;
    *) usage ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo -i first)." >&2
  exit 1
fi

STAMP="$(date +%F-%H%M%S)"
HOST="$(hostname -s)"
OUT="$BAK_ROOT/mail-$HOST-$STAMP"

umask 077                      # every file we create is root-only
mkdir -p "$OUT"
LOG="$OUT/backup.log"

log() { printf '[%s] %s\n' "$(date +%T)" "$*" | tee -a "$LOG"; }

# archive NAME PATH...  -> $OUT/NAME.tgz with only the paths that exist.
# tar exit 1 = "file changed as we read it", which is normal for live mail.
archive() {
  local name="$1"; shift
  local paths=() p
  for p in "$@"; do
    [[ -e "$p" || -L "$p" ]] && paths+=("${p#/}")   # strip leading / for tar -C /
  done
  if [[ ${#paths[@]} -eq 0 ]]; then
    log "skip $name (nothing found)"
    return
  fi
  tar --warning=no-file-changed -C / -czpf "$OUT/$name.tgz" "${paths[@]}" 2>>"$LOG"
  local rc=$?
  if [[ $rc -le 1 ]]; then
    log "ok   $name.tgz ($(du -h "$OUT/$name.tgz" | cut -f1)) <- ${paths[*]}"
  else
    log "FAIL $name.tgz (tar exit $rc) - see $LOG"
  fi
}

# snap FILE CMD...  -> save a command's output as a text file
snap() {
  local file="$1"; shift
  if command -v "$1" >/dev/null 2>&1; then
    "$@" >"$OUT/$file" 2>&1
    log "ok   $file"
  else
    log "skip $file ($1 not installed)"
  fi
}

log "Backing up $HOST to $OUT"

# 1. Snapshots of the running config -------------------------------------
snap postconf-n.txt     postconf -n          # Postfix settings that differ from defaults
snap postconf-M.txt     postconf -M          # master.cf services (red team adds listeners here)
snap doveconf-n.txt     doveconf -n          # Dovecot settings that differ from defaults
snap mail-queue.txt     postqueue -p         # what's waiting to be delivered
snap listening.txt      ss -tulpn            # ports open at backup time
snap packages.txt       dpkg -l              # installed package versions

# 2. Configs ---------------------------------------------------------------
archive mail-configs \
  /etc/postfix /etc/dovecot /etc/aliases /etc/aliases.db /etc/mailname \
  /etc/opendkim /etc/opendkim.conf /etc/default/opendkim \
  /etc/roundcube /etc/apache2 /etc/nginx /etc/spamassassin

# 3. Accounts --------------------------------------------------------------
archive accounts /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d

# 4. TLS certs and keys actually in use -------------------------------------
certs=(/etc/letsencrypt)
if command -v postconf >/dev/null 2>&1; then
  for k in smtpd_tls_cert_file smtpd_tls_key_file smtpd_tls_chain_files; do
    for f in $(postconf -h "$k" 2>/dev/null | tr ',' ' '); do certs+=("$f"); done
  done
fi
if command -v doveconf >/dev/null 2>&1; then
  for k in ssl_cert ssl_key; do
    f="$(doveconf -h "$k" 2>/dev/null)"
    certs+=("${f#<}")                     # Dovecot writes paths as "</path"
  done
fi
archive tls "${certs[@]}"

# 5. Mailboxes -------------------------------------------------------------
if [[ $SKIP_MAIL -eq 1 ]]; then
  log "skip mailboxes (-n)"
else
  boxes=(/var/mail /var/vmail /var/lib/roundcube)
  for d in /home/*/Maildir /home/*/mail; do boxes+=("$d"); done

  # Ask Dovecot where mail lives, e.g. "maildir:/var/vmail/%d/%n" -> /var/vmail
  if command -v doveconf >/dev/null 2>&1; then
    ml="$(doveconf -h mail_location 2>/dev/null)"
    log "dovecot mail_location = ${ml:-<empty>}"
    loc="${ml#*:}"; loc="${loc%%:*}"; loc="${loc%%\%*}"; loc="${loc%/}"
    [[ "$loc" == /* ]] && boxes+=("$loc")
  fi

  du -sh "${boxes[@]}" 2>/dev/null | tee -a "$LOG"
  archive mailboxes "${boxes[@]}"
fi

# 6. Hashes + restore notes ----------------------------------------------------
cat >"$OUT/RESTORE.txt" <<'EOF'
RESTORE CHEAT SHEET (run as root, from inside this backup folder)

Check nothing was tampered with:
  sha256sum -c SHA256SUMS

See what changed in the running config since this backup (great for spotting
red team edits, e.g. an open relay or a new listener):
  diff postconf-n.txt <(postconf -n)
  diff postconf-M.txt <(postconf -M)
  diff doveconf-n.txt <(doveconf -n)

Restore ONE config folder (example: Postfix), then validate and reload:
  tar -xzpf mail-configs.tgz -C / etc/postfix
  postfix check && systemctl reload postfix
  newaliases                         # if /etc/aliases was restored

Restore Dovecot config:
  tar -xzpf mail-configs.tgz -C / etc/dovecot
  doveconf -n >/dev/null && systemctl restart dovecot

Restore mailboxes (stop services first so nothing writes mid-restore):
  systemctl stop postfix dovecot
  tar -xzpf mailboxes.tgz -C /
  systemctl start postfix dovecot

List what's inside an archive without extracting:
  tar -tzf mail-configs.tgz | less
EOF

( cd "$OUT" && sha256sum -- *.tgz *.txt >SHA256SUMS 2>/dev/null )
log "ok   SHA256SUMS + RESTORE.txt"

# 7. Copy off the box ----------------------------------------------------------
if [[ -n "$REMOTE" ]]; then
  if scp -r "$OUT" "$REMOTE"; then
    log "ok   copied to $REMOTE"
  else
    log "FAIL scp to $REMOTE - copy $OUT manually"
  fi
fi

log "Done. Backup: $OUT"
grep -q FAIL "$LOG" && { echo "Some steps FAILED - check $LOG" >&2; exit 2; }
exit 0
