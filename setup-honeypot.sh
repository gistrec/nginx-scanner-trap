#!/usr/bin/env bash
# setup-honeypot.sh — turn an nginx box into a scanner trap, out of the box.
#
# What it does (Debian/Ubuntu):
#   1. Drops a honeypot `log_format` into /etc/nginx/conf.d/ (http context).
#      The log records: client IP, timestamp, and the probed request line.
#   2. Writes two server snippets: honeypot.conf (logs probes of /.env, /.git,
#      … → 404) and deny-dotfiles.conf (404 for any other dotfile, but keeps
#      /.well-known working for Let's Encrypt).
#   3. Wires both snippets into every server block in sites-enabled
#      (idempotent; backups go OUTSIDE nginx; `nginx -t` rollback on failure).
#   4. Installs + configures fail2ban: filter, jail (maxretry=1,
#      nftables-allports, incremental bans) reading the honeypot log.
#   5. Auto-detects YOUR IP and asks for any extra IPs to whitelist, so the
#      ban (which blocks ALL ports, SSH included) never locks you out.
#
# Usage:
#   sudo bash setup-honeypot.sh                 interactive (recommended)
#   curl -fsSL https://raw.githubusercontent.com/gistrec/nginx-scanner-trap/main/setup-honeypot.sh | sudo bash
#
#   --ip <ip>            your admin IP (skip auto-detection)
#   --extra "<ips>"      space-separated extra IPs/CIDRs to whitelist
#   --aggressive         also trap wp-login.php / phpmyadmin / xmlrpc.php
#                        (do NOT use if this host runs WordPress/phpMyAdmin)
#   --no-wire            don't touch sites-enabled; just print the include lines
#   --allow-no-whitelist proceed even if no admin IP gets whitelisted (risky)
#   --bantime <spec>     base ban time      (default 86400; accepts 1h/1d/1w)
#   --maxtime <spec>     max incremental ban (default 1w)
#   -y, --yes            assume yes, no prompts (uses detected/--ip + --extra)
#   --dry-run            show what would happen, change nothing
#   -h, --help           this help
#
# Repo:          https://github.com/gistrec/nginx-scanner-trap
# Write-up:      https://gistrec.cloud/blog/nginx-honeypot-fail2ban/

set -euo pipefail

# ── Config / paths ──────────────────────────────────────────────────────
CONFD_LOG=/etc/nginx/conf.d/honeypot-log.conf
SNIP_HONEYPOT=/etc/nginx/snippets/honeypot.conf
SNIP_DENY=/etc/nginx/snippets/deny-dotfiles.conf
HONEYPOT_LOG=/var/log/nginx/honeypot.log
SITES_DIR=/etc/nginx/sites-enabled
F2B_FILTER=/etc/fail2ban/filter.d/nginx-honeypot.conf
F2B_JAIL=/etc/fail2ban/jail.d/nginx-honeypot.conf
F2B_JAIL_LOCAL=/etc/fail2ban/jail.local

TS=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/var/backups/nginx-scanner-trap/$TS"

# ── Flags (use ${VAR:-default} so values carried across the sudo re-exec
#    via the environment are not clobbered on the second run) ─────────────
ADMIN_IP="${ADMIN_IP:-}"
EXTRA_IPS="${EXTRA_IPS:-}"
AGGRESSIVE="${AGGRESSIVE:-0}"
WIRE="${WIRE:-1}"
ALLOW_NO_WL="${ALLOW_NO_WL:-0}"
ASSUME_YES="${ASSUME_YES:-0}"
DRY_RUN="${DRY_RUN:-0}"
BANTIME="${BANTIME:-86400}"
MAXTIME="${MAXTIME:-1w}"

CHANGED=()    # "action|path|backup" records, for nginx rollback
TMPFILES=()   # mktemp files, cleaned on EXIT

# ── Pretty output ───────────────────────────────────────────────────────
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_B=$'\e[1m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
    C_RED=$'\e[31m'; C_CYN=$'\e[36m'; C_0=$'\e[0m'
else
    C_B=""; C_GRN=""; C_YEL=""; C_RED=""; C_CYN=""; C_0=""
fi
info() { printf '%s\n' "${C_CYN}··${C_0} $*"; }
ok()   { printf '%s\n' "${C_GRN}✓${C_0}  $*"; }
warn() { printf '%s\n' "${C_YEL}!${C_0}  $*" >&2; }
err()  { printf '%s\n' "${C_RED}✗${C_0}  $*" >&2; }
step() { printf '\n%s\n' "${C_B}▸ $*${C_0}"; }

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,"");print;next} {exit}' "$0"; }

cleanup() { local t; for t in "${TMPFILES[@]:-}"; do [[ -n "$t" ]] && rm -f "$t"; done; }
trap cleanup EXIT

# ── Arg parsing ─────────────────────────────────────────────────────────
need_val() { [[ $# -ge 2 && -n "${2:-}" ]] || { err "Option '$1' requires a value."; exit 2; }; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)                 need_val "$@"; ADMIN_IP="$2"; shift 2;;
        --extra)              need_val "$@"; EXTRA_IPS="$2"; shift 2;;
        --aggressive)         AGGRESSIVE=1; shift;;
        --no-wire)            WIRE=0; shift;;
        --allow-no-whitelist) ALLOW_NO_WL=1; shift;;
        --bantime)            need_val "$@"; BANTIME="$2"; shift 2;;
        --maxtime)            need_val "$@"; MAXTIME="$2"; shift 2;;
        -y|--yes)             ASSUME_YES=1; shift;;
        --dry-run)            DRY_RUN=1; shift;;
        -h|--help)            usage; exit 0;;
        *) err "Unknown option: $1"; echo "Run '$0 --help' for usage." >&2; exit 2;;
    esac
done

valid_time() { [[ "$1" =~ ^[0-9]+([smhdwy])?$ ]]; }
valid_time "$BANTIME" || { err "--bantime '$BANTIME' is not a valid time (e.g. 86400, 1h, 1d, 1w)."; exit 2; }
valid_time "$MAXTIME" || { err "--maxtime '$MAXTIME' is not a valid time (e.g. 86400, 1h, 1d, 1w)."; exit 2; }

# ── Detect admin IP BEFORE sudo strips the environment ──────────────────
detect_admin_ip() {
    local ip=""
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        ip=$(awk '{print $1}' <<<"$SSH_CONNECTION")
    elif [[ -n "${SSH_CLIENT:-}" ]]; then
        ip=$(awk '{print $1}' <<<"$SSH_CLIENT")
    fi
    if [[ -z "$ip" ]] && command -v who >/dev/null 2>&1; then
        ip=$(who am i 2>/dev/null | sed -n 's/.*(\(.*\)).*/\1/p')
    fi
    if [[ -z "$ip" ]] && command -v ss >/dev/null 2>&1; then
        # $3 = local address — anchor on OUR :22, so an outgoing ssh session
        # from this box (peer :22) can't donate a foreign IP to the whitelist.
        ip=$(ss -tnHo state established 2>/dev/null \
             | awk '$3 ~ /:22$/{print $4}' \
             | sed -E 's/.*:([0-9.]+|\[[0-9a-fA-F:]+\]):[0-9]+$/\1/; s/[][]//g' \
             | head -n1)
    fi
    ip=${ip#\[}; ip=${ip%\]}
    printf '%s' "$ip"
}
[[ -z "$ADMIN_IP" ]] && ADMIN_IP="$(detect_admin_ip)"

# ── Re-exec as root, carrying the detected IP and SSH env across sudo ────
if [[ $EUID -ne 0 ]]; then
    if [[ ! -f "$0" ]]; then
        err "Run me as root. When piping, send it into 'sudo bash':"
        err "  curl -fsSL https://raw.githubusercontent.com/gistrec/nginx-scanner-trap/main/setup-honeypot.sh | sudo bash"
        exit 1
    fi
    info "Re-running with sudo…"
    exec sudo --preserve-env=SSH_CONNECTION,SSH_CLIENT \
        ADMIN_IP="$ADMIN_IP" EXTRA_IPS="$EXTRA_IPS" AGGRESSIVE="$AGGRESSIVE" \
        WIRE="$WIRE" ALLOW_NO_WL="$ALLOW_NO_WL" ASSUME_YES="$ASSUME_YES" \
        DRY_RUN="$DRY_RUN" BANTIME="$BANTIME" MAXTIME="$MAXTIME" \
        NO_COLOR="${NO_COLOR:-}" bash "$0" "$@"
fi

# ── Terminal & python availability ──────────────────────────────────────
if (: </dev/tty) 2>/dev/null; then HAVE_TTY=1; else HAVE_TTY=0; fi
if [[ $ASSUME_YES -eq 0 && $HAVE_TTY -eq 0 ]]; then
    err "No terminal available for prompts. Re-run with -y (and --ip/--extra) for non-interactive use."
    exit 2
fi
_PYOK=""; command -v python3 >/dev/null 2>&1 && _PYOK=1

# ── Helpers ─────────────────────────────────────────────────────────────
run() { if [[ $DRY_RUN -eq 1 ]]; then info "[dry-run] $*"; else "$@"; fi; }

ask() {  # $1 = prompt → echoes the typed answer (reads the real terminal)
    local ans=""
    [[ $HAVE_TTY -eq 1 ]] && { read -r -p "$1" ans </dev/tty || ans=""; }
    printf '%s' "$ans"
}
confirm() {  # $1 = prompt → 0 if yes (default yes)
    [[ $ASSUME_YES -eq 1 ]] && return 0
    [[ $HAVE_TTY -eq 1 ]] || return 1
    local ans; ans=$(ask "$1 [Y/n] ")
    [[ -z "$ans" || "$ans" =~ ^[Yy] ]]
}

valid_ipv4() {
    local ip="$1" pfx="" o
    if [[ "$ip" == */* ]]; then
        pfx="${ip#*/}"; ip="${ip%/*}"
        [[ "$pfx" =~ ^[0-9]+$ ]] && (( 10#$pfx >= 0 && 10#$pfx <= 32 )) || return 1
    fi
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    local oc; IFS=. read -ra oc <<<"$ip"
    for o in "${oc[@]}"; do [[ "$o" =~ ^[0-9]+$ ]] && (( 10#$o >= 0 && 10#$o <= 255 )) || return 1; done
    return 0
}
valid_ip() {  # authoritative via python3 if present, else a bash fallback
    local x="$1"
    if [[ -n "$_PYOK" ]]; then
        printf '%s' "$x" | python3 -c 'import sys, ipaddress
try:
    ipaddress.ip_network(sys.stdin.read().strip(), strict=False)
except ValueError:
    sys.exit(1)' 2>/dev/null
        return $?
    fi
    valid_ipv4 "$x" && return 0
    [[ "$x" == *:* && "$x" =~ ^[0-9a-fA-F:/]+$ ]] && return 0
    return 1
}

REPLY_BACKUP=""
do_backup() {  # $1 = existing file → copy under BACKUP_DIR, set REPLY_BACKUP
    local b="$BACKUP_DIR$1"
    mkdir -p "$(dirname "$b")"
    cp -a "$1" "$b"
    REPLY_BACKUP="$b"
}

write_file() {  # $1 = path, $2 = mode; content on stdin
    local path="$1" mode="${2:-0644}" tmp
    tmp=$(mktemp); TMPFILES+=("$tmp")
    cat >"$tmp"
    if [[ $DRY_RUN -eq 1 ]]; then
        info "[dry-run] would write ${C_B}$path${C_0}:"; sed 's/^/      /' "$tmp"; return 0
    fi
    if [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then info "unchanged: $path"; return 0; fi
    if [[ -e "$path" ]]; then
        do_backup "$path"; CHANGED+=("modified|$path|$REPLY_BACKUP"); info "backup → $REPLY_BACKUP"
    else
        CHANGED+=("created|$path|")
    fi
    install -D -m "$mode" "$tmp" "$path"
    ok "wrote $path"
}

ensure_pkg() {  # $1 = package, $2 = binary to probe (optional)
    local pkg="$1" bin="${2:-$1}"
    if command -v "$bin" >/dev/null 2>&1 || dpkg -s "$pkg" >/dev/null 2>&1; then
        info "present: $pkg"; return 0
    fi
    info "installing: $pkg"; run apt-get update -qq; run apt-get install -y -qq "$pkg"
}

# ── Preconditions ───────────────────────────────────────────────────────
step "Checks"
command -v nginx >/dev/null 2>&1 || { err "nginx not found — install/configure nginx first."; exit 1; }
command -v apt-get >/dev/null 2>&1 || { err "apt-get not found — this script targets Debian/Ubuntu."; exit 1; }
ok "nginx and apt-get present"
warn "If this nginx is behind Cloudflare or a reverse proxy, configure real_ip"
warn "(set_real_ip_from + real_ip_header) FIRST — otherwise the honeypot records"
warn "the proxy's IP and fail2ban will ban your proxy/CDN, not the scanner."

# ── Build the whitelist ─────────────────────────────────────────────────
step "Whitelist (the ban blocks ALL ports, SSH too — don't lock yourself out)"

if [[ -n "$ADMIN_IP" ]]; then
    info "Detected your IP: ${C_B}$ADMIN_IP${C_0}"
    confirm "Whitelist this IP?" || ADMIN_IP=""
else
    warn "Could not auto-detect your IP."
fi
if [[ -z "$ADMIN_IP" && $ASSUME_YES -eq 0 && $HAVE_TTY -eq 1 ]]; then
    while :; do
        ADMIN_IP=$(ask "Enter your admin IP (or leave empty to skip): ")
        [[ -z "$ADMIN_IP" ]] && break
        valid_ip "$ADMIN_IP" && break
        warn "Not a valid IP/CIDR: $ADMIN_IP"
    done
fi
if [[ $ASSUME_YES -eq 0 && $HAVE_TTY -eq 1 ]]; then
    extra_in=$(ask "Extra IPs/CIDRs to whitelist (space-separated, empty = none): ")
    EXTRA_IPS="${EXTRA_IPS:+$EXTRA_IPS }$extra_in"
fi

IGNORE_LIST=(127.0.0.1/8 ::1)
admin_count=0
set -f  # word-split is intended here; -f keeps a typo like 1.2.3.* from
        # globbing into filenames from the cwd
for cand in $ADMIN_IP $EXTRA_IPS; do
    [[ -z "$cand" ]] && continue
    if valid_ip "$cand"; then IGNORE_LIST+=("$cand"); admin_count=$((admin_count + 1))
    else warn "skipping invalid: $cand"; fi
done
set +f
IGNOREIP=$(printf '%s\n' "${IGNORE_LIST[@]}" | awk '!seen[$0]++' | paste -sd' ' -)

if [[ $admin_count -eq 0 ]]; then
    warn "No admin IP will be whitelisted — fail2ban bans on ALL ports, so the"
    warn "first probe from your own network would lock you out (SSH included)."
    if [[ $ALLOW_NO_WL -eq 1 ]]; then
        warn "Proceeding anyway (--allow-no-whitelist)."
    elif [[ $ASSUME_YES -eq 1 ]]; then
        err "Refusing to run with no whitelist in -y mode. Pass --ip <ip> or --allow-no-whitelist."
        exit 2
    elif ! confirm "Proceed with NO admin IP whitelisted?"; then
        info "Aborted."; exit 0
    fi
fi
ok "ignoreip = ${C_B}$IGNOREIP${C_0}"

# ── Plan / confirm ──────────────────────────────────────────────────────
step "Plan"
cat <<PLAN
  nginx log format : $CONFD_LOG   (IP, time, request)
  nginx snippets   : $SNIP_HONEYPOT$([[ $AGGRESSIVE -eq 1 ]] && echo "  [+aggressive]")
                     $SNIP_DENY
  honeypot log     : $HONEYPOT_LOG
  wire into sites  : $([[ $WIRE -eq 1 ]] && echo "yes ($SITES_DIR/*)" || echo "no (manual)")
  fail2ban jail    : $F2B_JAIL  (maxretry=1, bantime=$BANTIME, max=$MAXTIME)
  ban backend      : nftables-allports (all ports)
  whitelist        : $IGNOREIP
  backups          : $BACKUP_DIR
PLAN
[[ $DRY_RUN -eq 1 ]] && warn "DRY RUN — nothing will be changed."
confirm "Proceed?" || { info "Aborted."; exit 0; }

# ── Packages ────────────────────────────────────────────────────────────
step "Packages"
ensure_pkg fail2ban fail2ban-client
ensure_pkg nftables nft

# ── nginx: log format + snippets + log file ─────────────────────────────
step "nginx config"

write_file "$CONFD_LOG" 0644 <<'NGINX'
# Honeypot log: client IP, timestamp, and the probed request — written only
# to honeypot.log by the honeypot location. The real timestamp lets fail2ban
# use a proper date (no datepattern={NONE}), so a log re-scan does not re-ban
# IPs whose bans already expired.
log_format honeypot '$remote_addr - [$time_local] "$request"';
NGINX

# honeypot.conf — safe set always; wp-login/phpmyadmin only with --aggressive,
# since those can be legitimate and would 404+ban real admins otherwise.
# Built in a variable (not piped into write_file, which would run it in a
# subshell and lose its CHANGED/TMPFILES bookkeeping).
honeypot_conf=$(cat <<'NGINX'
# Honeypot: log probes for paths a real client never requests, then 404.
# Prefix match (no trailing $) — catches /.git/config, /.env.local, etc.
# Must be included BEFORE deny-dotfiles.conf so these hits get logged first.
location ~* ^/(\.env|\.git|\.aws|\.ssh|config\.php\.bak|backup\.sql) {
    access_log /var/log/nginx/honeypot.log honeypot;
    return 404;
}
NGINX
)
if [[ $AGGRESSIVE -eq 1 ]]; then
    honeypot_conf+='

# Aggressive extras (enabled via --aggressive). Remove if this host ever
# serves WordPress/phpMyAdmin to real users.
location ~* ^/(wp-login\.php|phpmyadmin|xmlrpc\.php) {
    access_log /var/log/nginx/honeypot.log honeypot;
    return 404;
}'
else
    honeypot_conf+='

# Aggressive extras — paths that CAN be legitimate. Uncomment ONLY if this
# host does NOT run WordPress/phpMyAdmin (or re-run with --aggressive):
#location ~* ^/(wp-login\.php|phpmyadmin|xmlrpc\.php) {
#    access_log /var/log/nginx/honeypot.log honeypot;
#    return 404;
#}'
fi
write_file "$SNIP_HONEYPOT" 0644 <<<"$honeypot_conf"

write_file "$SNIP_DENY" 0644 <<'NGINX'
# Block access to dotfiles (.git, .env, .ssh, …). 404 (not 403) so scanners
# can't confirm a file exists. The (?!well-known) negative lookahead keeps
# Let's Encrypt HTTP-01 (/.well-known/acme-challenge/) working.
# Must be included AFTER honeypot.conf — first matching regex location wins.
location ~ /\.(?!well-known) {
    return 404;
}
NGINX

# Pre-create the log so fail2ban has something to watch from the start.
# It lives in /var/log/nginx so the distro's existing logrotate covers it.
if [[ $DRY_RUN -eq 0 && ! -e "$HONEYPOT_LOG" ]]; then
    install -D -m 0640 /dev/null "$HONEYPOT_LOG"
    if id www-data >/dev/null 2>&1; then chown www-data:adm "$HONEYPOT_LOG" 2>/dev/null || true; fi
    ok "created $HONEYPOT_LOG"
fi

# Sanity: is the honeypot format actually in scope? Capture nginx -T to a
# variable first (a `... | grep -q` pipeline would SIGPIPE nginx -T and, under
# pipefail, look like a failure even when the format IS present).
if [[ $DRY_RUN -eq 0 ]]; then
    nginx_dump=$(nginx -T 2>/dev/null || true)
    if ! grep -Eq 'log_format[[:space:]]+honeypot' <<<"$nginx_dump"; then
        warn "log_format 'honeypot' isn't visible in the effective config —"
        warn "your nginx.conf may not include $CONFD_LOG (conf.d/*.conf)."
        warn "Add this line inside the http { } block manually, then re-run:"
        warn "    log_format honeypot '\$remote_addr - [\$time_local] \"\$request\"';"
    fi
fi

# ── Wire the snippets into every server block ───────────────────────────
wire_one() {  # $1 = real config file
    local real="$1" tmp
    if grep -q 'snippets/honeypot.conf' "$real"; then
        info "already wired: $real"; wired_count=$((wired_count + 1)); return 0
    fi
    if grep -Eq '^[[:space:]]*stream[[:space:]]*\{' "$real"; then
        warn "contains a stream {} block, skipped (location is invalid there): $real"; return 0
    fi
    if grep -Eq '^[[:space:]]*server[[:space:]]*\{[^}]*\}' "$real"; then
        warn "one-line server block, skipped (add the includes manually): $real"; return 0
    fi
    tmp=$(mktemp); TMPFILES+=("$tmp")
    # Handles `server {` and Allman-style `server` on its own line then `{`.
    awk -v inc="    include /etc/nginx/snippets/honeypot.conf;\n    include /etc/nginx/snippets/deny-dotfiles.conf;" '
        /^[[:space:]]*server[[:space:]]*\{/ { print; print inc; next }
        /^[[:space:]]*server[[:space:]]*$/  { print; awaiting=1; next }
        awaiting && /\{/                    { print; print inc; awaiting=0; next }
        { print }
    ' "$real" >"$tmp"
    if cmp -s "$tmp" "$real"; then warn "no server block, skipped: $real"; return 0; fi
    if [[ $DRY_RUN -eq 1 ]]; then
        info "[dry-run] would wire $real"; wired_count=$((wired_count + 1)); return 0
    fi
    do_backup "$real"; CHANGED+=("modified|$real|$REPLY_BACKUP")
    cat "$tmp" >"$real"
    wired_count=$((wired_count + 1))
    ok "wired $real (backup → $REPLY_BACKUP)"
    if grep -Eq '^[[:space:]]*return[[:space:]]+30[0-9]' "$real"; then
        warn "↳ $real looks like a redirect vhost — a server-level 'return' runs before"
        warn "  the honeypot location, so port-80 probes there are 301'd, not trapped"
        warn "  (they're caught on your HTTPS vhost instead)."
    fi
}

wired_count=0
if [[ $WIRE -eq 1 ]]; then
    step "Wiring snippets into $SITES_DIR/*"
    shopt -s nullglob
    found=0
    for f in "$SITES_DIR"/*; do
        real=$(readlink -f "$f" 2>/dev/null || echo "$f")
        [[ -f "$real" ]] || continue
        found=1; wire_one "$real"
    done
    shopt -u nullglob
    [[ $found -eq 0 ]] && warn "no files in $SITES_DIR — nothing to wire."
else
    step "Skipping auto-wire (--no-wire). Add these two lines to each server { } block:"
    printf '    include %s;\n    include %s;\n' "$SNIP_HONEYPOT" "$SNIP_DENY"
fi

# ── Validate nginx, rolling back everything we created on failure ────────
rollback_nginx() {
    local rec action rest path backup i
    for (( i=${#CHANGED[@]}-1; i>=0; i-- )); do
        rec="${CHANGED[$i]}"; action="${rec%%|*}"; rest="${rec#*|}"
        path="${rest%%|*}"; backup="${rest#*|}"
        case "$action" in
            modified) cp -a "$backup" "$path" && warn "restored $path";;
            created)  rm -f "$path" && warn "removed $path";;
        esac
    done
}

step "nginx -t"
if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] would run: nginx -t && systemctl reload nginx"
elif nginx -t; then
    ok "config valid"; run systemctl reload nginx; ok "nginx reloaded"
else
    err "nginx -t failed — rolling back everything this script created."
    rollback_nginx
    if nginx -t; then warn "rolled back to a valid config."; else err "still invalid — inspect manually."; fi
    exit 1
fi

# ── fail2ban: filter + jail (+ global whitelist) ────────────────────────
step "fail2ban config"

write_file "$F2B_FILTER" 0644 <<'CONF'
# honeypot.log lines look like: IP - [time] "METHOD URI"
# <HOST> = the leading client IP; the [time] is auto-detected by fail2ban.
[Definition]
failregex = ^<HOST> -
CONF

write_file "$F2B_JAIL" 0644 <<CONF
# Managed by setup-honeypot.sh — re-running the script overwrites this file.
[nginx-honeypot]
enabled   = true
filter    = nginx-honeypot
logpath   = $HONEYPOT_LOG
# Force a file backend. The distro default is often 'systemd' (it is on
# Debian/Ubuntu), which makes the jail read the journal and miss this
# file-based honeypot log entirely — 0 hits, 0 bans. 'auto' picks
# pyinotify/polling on the file and never resolves to systemd.
backend   = auto
maxretry  = 1
bantime   = $BANTIME
banaction = nftables-allports
bantime.increment = true
bantime.maxtime   = $MAXTIME
ignoreip  = $IGNOREIP
CONF

# Global whitelist for ALL jails (incl. sshd). Only the ignoreip goes into
# [DEFAULT]; banaction stays scoped to our jail so we don't silently change
# how other jails (e.g. sshd) ban. Created only if jail.local is absent.
if [[ ! -e "$F2B_JAIL_LOCAL" ]]; then
    write_file "$F2B_JAIL_LOCAL" 0644 <<CONF
[DEFAULT]
ignoreip = $IGNOREIP
CONF
else
    warn "$F2B_JAIL_LOCAL exists — left untouched."
    warn "For a global whitelist, ensure its [DEFAULT] ignoreip includes:"
    warn "    $IGNOREIP"
fi

[[ -e /etc/fail2ban/action.d/nftables-allports.conf ]] || {
    warn "action 'nftables-allports' not found in /etc/fail2ban/action.d —"
    warn "this fail2ban build has no nftables actions; the jail will fail to load."
}

# bantime.increment / bantime.maxtime need fail2ban >= 0.11 — older versions
# ignore the keys, so every ban would last the fixed base bantime. Say so
# instead of guessing at versions (the jail itself still works).
f2b_ver=""
if command -v fail2ban-client >/dev/null 2>&1; then
    f2b_ver=$(fail2ban-client --version 2>/dev/null | grep -Eom1 '[0-9]+(\.[0-9]+)+' || true)
fi
if [[ -n "$f2b_ver" && "$(printf '%s\n' "$f2b_ver" 0.11 | sort -V | head -n1)" != "0.11" ]]; then
    warn "fail2ban $f2b_ver < 0.11: incremental bans (bantime.increment/maxtime)"
    warn "aren't supported and are ignored — every ban lasts bantime=$BANTIME."
fi

# ── Start / reload fail2ban, then VERIFY the jail actually loaded ───────
step "Starting fail2ban"
if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] would: systemctl enable --now fail2ban && fail2ban-client reload && verify jail watches the log file"
else
    run systemctl enable --now fail2ban
    if ! systemctl reload fail2ban 2>/dev/null && ! fail2ban-client reload 2>/dev/null; then
        run systemctl restart fail2ban
    fi
    # Pull the jail status (retry: right after a restart the server socket can
    # need a moment before it answers).
    jail_status=""
    for _ in 1 2 3 4 5; do
        jail_status=$(fail2ban-client status nginx-honeypot 2>/dev/null) || jail_status=""
        if [[ -n "$jail_status" ]]; then break; fi
        sleep 1
    done

    if [[ -z "$jail_status" ]]; then
        err "jail nginx-honeypot did NOT load — the honeypot will log but never ban."
        err "Check: sudo fail2ban-client status   and   sudo journalctl -u fail2ban -n 50"
        exit 1
    fi
    ok "jail nginx-honeypot is loaded"

    # Loaded isn't enough: the jail must WATCH THE FILE, not the systemd
    # journal. If the distro default backend is 'systemd' (it is on
    # Debian/Ubuntu) and the jail doesn't override it, fail2ban reads the
    # journal and silently ignores this file-based log — probes get logged,
    # but 'Total failed' stays 0 and nothing is ever banned. The honeypot log
    # must show up in the jail's monitored "File list".
    if ! grep -qF "$HONEYPOT_LOG" <<<"$jail_status"; then
        err "jail nginx-honeypot is NOT watching $HONEYPOT_LOG — it will log but never ban."
        if grep -q 'Journal matches:' <<<"$jail_status"; then
            err "It's on the systemd backend (reading the journal), so file-based"
            err "honeypot hits are invisible to it."
        fi
        err "Fix: ensure 'backend = auto' is set in $F2B_JAIL, then restart fail2ban."
        err "Verify: sudo fail2ban-client status nginx-honeypot"
        err "        → expect 'File list: $HONEYPOT_LOG'"
        exit 1
    fi
    ok "jail nginx-honeypot is watching $HONEYPOT_LOG (file backend)"
fi

# ── Summary ─────────────────────────────────────────────────────────────
step "Done"
if [[ $DRY_RUN -eq 1 ]]; then
    info "Dry run complete. Re-run without --dry-run to apply."; exit 0
fi
if [[ $WIRE -eq 0 ]]; then
    cat <<DONE
  ${C_YEL}Snippets and the fail2ban jail are installed, but NOT wired into any
  server block (--no-wire).${C_0} The honeypot is INACTIVE until you add:
    include $SNIP_HONEYPOT;
    include $SNIP_DENY;
  to each server { } block, then: sudo nginx -t && sudo systemctl reload nginx
DONE
elif [[ $wired_count -eq 0 ]]; then
    cat <<DONE
  ${C_YEL}Snippets and the fail2ban jail are installed, but NO server block got
  the includes${C_0} — $SITES_DIR is empty or every file was skipped (see
  warnings above). The honeypot is INACTIVE until you add:
    include $SNIP_HONEYPOT;
    include $SNIP_DENY;
  to each server { } block, then: sudo nginx -t && sudo systemctl reload nginx
DONE
else
    cat <<DONE
  ${C_GRN}Honeypot is live${C_0} — wired into $wired_count file(s) in $SITES_DIR.
  A probe to /.env, /.git, … gets one 404; its IP, the time, and the request
  land in $HONEYPOT_LOG, and fail2ban bans it on all ports.
  Whitelisted (never banned): ${C_B}$IGNOREIP${C_0}
DONE
fi
cat <<DONE

  Check it:
    sudo fail2ban-client status nginx-honeypot
    sudo nft list table inet f2b-table
  Unban:
    sudo fail2ban-client set nginx-honeypot unbanip <IP>
    sudo fail2ban-client unban --all
DONE
