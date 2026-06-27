#!/usr/bin/env bash
# setup-honeypot.sh — turn an nginx box into a scanner trap, out of the box.
#
# What it does (Debian/Ubuntu):
#   1. Drops a honeypot `log_format` into /etc/nginx/conf.d/ (http context).
#   2. Writes two server snippets: honeypot.conf (logs scanners of /.env,
#      /.git, /wp-login.php… → 404) and deny-dotfiles.conf (404 for any /.*).
#   3. Wires both snippets into every server block in sites-enabled
#      (idempotent, with per-file backups and an `nginx -t` rollback).
#   4. Installs + configures fail2ban: filter, jail (maxretry=1,
#      nftables-allports, incremental bans) reading the honeypot log.
#   5. Auto-detects YOUR IP and asks for any extra IPs to whitelist, so the
#      ban (which blocks ALL ports, SSH included) never locks you out.
#
# Usage:
#   sudo bash setup-honeypot.sh                 interactive (recommended)
#   curl -fsSL https://raw.githubusercontent.com/gistrec/nginx-scanner-trap/main/setup-honeypot.sh | sudo bash
#
#   --ip <ip>          your admin IP (skip auto-detection)
#   --extra "<ips>"    space-separated extra IPs/CIDRs to whitelist
#   --no-wire          don't touch sites-enabled; just print the include lines
#   --bantime <sec>    base ban time      (default 86400 = 24h)
#   --maxtime <spec>   max incremental ban (default 1w)
#   -y, --yes          assume yes, no prompts (uses detected/--ip + --extra)
#   --dry-run          show what would happen, change nothing
#   -h, --help         this help
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

# ── Flags (use ${VAR:-default} so values carried across the sudo re-exec
#    via the environment are not clobbered on the second run) ─────────────
ADMIN_IP="${ADMIN_IP:-}"
EXTRA_IPS="${EXTRA_IPS:-}"
WIRE="${WIRE:-1}"
ASSUME_YES="${ASSUME_YES:-0}"
DRY_RUN="${DRY_RUN:-0}"
BANTIME="${BANTIME:-86400}"
MAXTIME="${MAXTIME:-1w}"
SITE_BACKUPS=()   # "real|backup" pairs, for rollback

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

# ── Arg parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)        ADMIN_IP="${2:-}"; shift 2;;
        --extra)     EXTRA_IPS="${2:-}"; shift 2;;
        --no-wire)   WIRE=0; shift;;
        --bantime)   BANTIME="${2:-}"; shift 2;;
        --maxtime)   MAXTIME="${2:-}"; shift 2;;
        -y|--yes)    ASSUME_YES=1; shift;;
        --dry-run)   DRY_RUN=1; shift;;
        -h|--help)   usage; exit 0;;
        *) err "Unknown option: $1"; echo "Run '$0 --help' for usage." >&2; exit 2;;
    esac
done

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
        ip=$(ss -tnHo state established 2>/dev/null \
             | awk '$1 ~ /ssh|:22$/ || $0 ~ /:22 /{print $4}' \
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
        ADMIN_IP="$ADMIN_IP" EXTRA_IPS="$EXTRA_IPS" WIRE="$WIRE" \
        ASSUME_YES="$ASSUME_YES" DRY_RUN="$DRY_RUN" \
        BANTIME="$BANTIME" MAXTIME="$MAXTIME" NO_COLOR="${NO_COLOR:-}" \
        bash "$0" "$@"
fi

# ── Helpers ─────────────────────────────────────────────────────────────
run() { if [[ $DRY_RUN -eq 1 ]]; then info "[dry-run] $*"; else "$@"; fi; }

ask() {  # $1 = prompt → echoes the typed answer (reads the real terminal)
    local ans=""
    if [[ -e /dev/tty ]]; then read -r -p "$1" ans </dev/tty || ans=""; fi
    printf '%s' "$ans"
}
confirm() {  # $1 = prompt → 0 if yes (default yes)
    [[ $ASSUME_YES -eq 1 ]] && return 0
    local ans; ans=$(ask "$1 [Y/n] ")
    [[ -z "$ans" || "$ans" =~ ^[Yy] ]]
}

valid_ipv4() {
    local ip="$1" pfx="" o
    if [[ "$ip" == */* ]]; then
        pfx="${ip#*/}"; ip="${ip%/*}"
        [[ "$pfx" =~ ^[0-9]+$ ]] && (( pfx >= 0 && pfx <= 32 )) || return 1
    fi
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    local oc; IFS=. read -ra oc <<<"$ip"
    for o in "${oc[@]}"; do [[ "$o" =~ ^[0-9]+$ ]] && (( o >= 0 && o <= 255 )) || return 1; done
    return 0
}
valid_ip() {  # IPv4, IPv4/CIDR, or (loosely) IPv6
    valid_ipv4 "$1" && return 0
    [[ "$1" == *:* && "$1" =~ ^[0-9a-fA-F:/]+$ ]] && return 0
    return 1
}

write_file() {  # $1 = path, $2 = mode; content on stdin
    local path="$1" mode="${2:-0644}" tmp
    tmp=$(mktemp)
    cat >"$tmp"
    if [[ $DRY_RUN -eq 1 ]]; then
        info "[dry-run] would write ${C_B}$path${C_0}:"
        sed 's/^/      /' "$tmp"; rm -f "$tmp"; return 0
    fi
    if [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then
        info "unchanged: $path"; rm -f "$tmp"; return 0
    fi
    [[ -f "$path" ]] && { cp -a "$path" "$path.bak.$TS"; info "backup → $path.bak.$TS"; }
    install -D -m "$mode" "$tmp" "$path"
    rm -f "$tmp"
    ok "wrote $path"
}

ensure_pkg() {  # $1 = package, $2 = binary to probe (optional)
    local pkg="$1" bin="${2:-$1}"
    if command -v "$bin" >/dev/null 2>&1 || dpkg -s "$pkg" >/dev/null 2>&1; then
        info "present: $pkg"; return 0
    fi
    info "installing: $pkg"
    run apt-get update -qq
    run apt-get install -y -qq "$pkg"
}

# ── Preconditions ───────────────────────────────────────────────────────
step "Checks"
command -v nginx >/dev/null 2>&1 || { err "nginx not found — install/configure nginx first."; exit 1; }
command -v apt-get >/dev/null 2>&1 || { err "apt-get not found — this script targets Debian/Ubuntu."; exit 1; }
ok "nginx and apt-get present"

# ── Build the whitelist ─────────────────────────────────────────────────
step "Whitelist (so the ban never locks you out — it blocks ALL ports, SSH too)"

if [[ -n "$ADMIN_IP" ]]; then
    info "Detected your IP: ${C_B}$ADMIN_IP${C_0}"
    if ! confirm "Whitelist this IP?"; then ADMIN_IP=""; fi
else
    warn "Could not auto-detect your IP."
fi
if [[ -z "$ADMIN_IP" && $ASSUME_YES -eq 0 ]]; then
    while :; do
        ADMIN_IP=$(ask "Enter your admin IP (or leave empty to skip): ")
        [[ -z "$ADMIN_IP" ]] && break
        valid_ip "$ADMIN_IP" && break
        warn "Not a valid IP/CIDR: $ADMIN_IP"
    done
fi

if [[ $ASSUME_YES -eq 0 ]]; then
    extra_in=$(ask "Extra IPs/CIDRs to whitelist (space-separated, empty = none): ")
    EXTRA_IPS="${EXTRA_IPS:+$EXTRA_IPS }$extra_in"
fi

# Validate everything; start from localhost, which must always be allowed.
IGNORE_LIST=(127.0.0.1/8 ::1)
for cand in $ADMIN_IP $EXTRA_IPS; do
    [[ -z "$cand" ]] && continue
    if valid_ip "$cand"; then IGNORE_LIST+=("$cand"); else warn "skipping invalid: $cand"; fi
done
# de-duplicate, preserve order
IGNOREIP=$(printf '%s\n' "${IGNORE_LIST[@]}" | awk '!seen[$0]++' | paste -sd' ' -)
ok "ignoreip = ${C_B}$IGNOREIP${C_0}"

# ── Plan / confirm ──────────────────────────────────────────────────────
step "Plan"
cat <<PLAN
  nginx log format : $CONFD_LOG
  nginx snippets   : $SNIP_HONEYPOT
                     $SNIP_DENY
  honeypot log     : $HONEYPOT_LOG
  wire into sites  : $([[ $WIRE -eq 1 ]] && echo "yes ($SITES_DIR/*)" || echo "no (manual)")
  fail2ban filter  : $F2B_FILTER
  fail2ban jail    : $F2B_JAIL  (maxretry=1, bantime=$BANTIME, max=$MAXTIME)
  ban backend      : nftables-allports (all ports)
  whitelist        : $IGNOREIP
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
# Honeypot access log: one IP per line, nothing else — that's all fail2ban
# needs, and it keeps the file tiny. log_format must live in http context.
log_format honeypot '$remote_addr';
NGINX

write_file "$SNIP_HONEYPOT" 0644 <<'NGINX'
# Honeypot: log scanner probes for sensitive paths, return 404.
# Prefix match (no trailing $) — catches /.git/config, /.env.local, etc.
# Must be included BEFORE deny-dotfiles.conf so these hits land in honeypot.log.
location ~* ^/(\.env|\.git|\.aws|\.ssh|wp-login\.php|phpmyadmin|config\.php\.bak|backup\.sql) {
    access_log /var/log/nginx/honeypot.log honeypot;
    return 404;
}
NGINX

write_file "$SNIP_DENY" 0644 <<'NGINX'
# Block access to dotfiles (.git, .env, .ssh, etc.)
# Returns 404 instead of 403 so scanners can't confirm file existence.
# Must be included AFTER honeypot.conf — nginx picks the first matching
# regex location, and honeypot patterns need to log before this catches them.
location ~ /\. {
    return 404;
}
NGINX

# Pre-create the log so fail2ban has something to watch from the start.
if [[ $DRY_RUN -eq 0 && ! -e "$HONEYPOT_LOG" ]]; then
    install -D -m 0640 /dev/null "$HONEYPOT_LOG"
    if id www-data >/dev/null 2>&1; then chown www-data:adm "$HONEYPOT_LOG" || true; fi
    ok "created $HONEYPOT_LOG"
fi

# Sanity: is the honeypot format actually in scope? (Catches the rare case
# where nginx.conf doesn't include conf.d/*.conf — otherwise the snippet's
# `access_log … honeypot` would fail nginx -t with a cryptic error.)
if [[ $DRY_RUN -eq 0 ]] && ! nginx -T 2>/dev/null | grep -Eq 'log_format[[:space:]]+honeypot'; then
    warn "log_format 'honeypot' isn't visible in the effective config —"
    warn "your nginx.conf may not include $CONFD_LOG (conf.d/*.conf)."
    warn "Add this line inside the http { } block manually, then re-run:"
    warn "    log_format honeypot '\$remote_addr';"
fi

# ── Wire the snippets into every server block ───────────────────────────
wire_one() {  # $1 = real config file
    local real="$1" tmp
    if grep -q 'snippets/honeypot.conf' "$real"; then info "already wired: $real"; return 0; fi
    if ! grep -Eq '^[[:space:]]*server[[:space:]]*\{' "$real"; then
        warn "no server block, skipped: $real"; return 0
    fi
    tmp=$(mktemp)
    awk '
        /^[[:space:]]*server[[:space:]]*\{/ {
            print
            print "    include /etc/nginx/snippets/honeypot.conf;"
            print "    include /etc/nginx/snippets/deny-dotfiles.conf;"
            next
        }
        { print }
    ' "$real" >"$tmp"
    if [[ $DRY_RUN -eq 1 ]]; then
        info "[dry-run] would wire $real"; rm -f "$tmp"; return 0
    fi
    cp -a "$real" "$real.bak.$TS"
    cat "$tmp" >"$real"; rm -f "$tmp"
    SITE_BACKUPS+=("$real|$real.bak.$TS")
    ok "wired $real (backup → $real.bak.$TS)"
}

if [[ $WIRE -eq 1 ]]; then
    step "Wiring snippets into $SITES_DIR/*"
    shopt -s nullglob
    found=0
    for f in "$SITES_DIR"/*; do
        real=$(readlink -f "$f" 2>/dev/null || echo "$f")
        [[ -f "$real" ]] || continue
        found=1
        wire_one "$real"
    done
    shopt -u nullglob
    [[ $found -eq 0 ]] && warn "no files in $SITES_DIR — nothing to wire."
else
    step "Skipping auto-wire (--no-wire). Add these two lines to each server { } block:"
    printf '    include %s;\n    include %s;\n' "$SNIP_HONEYPOT" "$SNIP_DENY"
fi

# ── Validate nginx, rolling back site edits on failure ──────────────────
step "nginx -t"
if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] would run: nginx -t && systemctl reload nginx"
elif nginx -t; then
    ok "config valid"
    run systemctl reload nginx
    ok "nginx reloaded"
else
    err "nginx -t failed — rolling back site edits."
    for pair in "${SITE_BACKUPS[@]:-}"; do
        [[ -z "$pair" ]] && continue
        cp -a "${pair#*|}" "${pair%|*}" && warn "restored ${pair%|*}"
    done
    if nginx -t; then warn "rolled back to a valid config."; else err "still invalid — inspect manually."; fi
    exit 1
fi

# ── fail2ban: filter + jail (+ global whitelist) ────────────────────────
step "fail2ban config"

write_file "$F2B_FILTER" 0644 <<'CONF'
[Definition]
failregex = ^<HOST>
datepattern = {NONE}
CONF

write_file "$F2B_JAIL" 0644 <<CONF
# Managed by setup-honeypot.sh — re-running the script overwrites this file.
[nginx-honeypot]
enabled   = true
filter    = nginx-honeypot
logpath   = $HONEYPOT_LOG
maxretry  = 1
bantime   = $BANTIME
banaction = nftables-allports
bantime.increment = true
bantime.maxtime   = $MAXTIME
ignoreip  = $IGNOREIP
CONF

# Global whitelist for ALL jails (incl. sshd): only create jail.local if it
# doesn't already exist, so we never clobber an existing fail2ban setup.
if [[ ! -e "$F2B_JAIL_LOCAL" ]]; then
    write_file "$F2B_JAIL_LOCAL" 0644 <<CONF
[DEFAULT]
banaction = nftables-allports
ignoreip  = $IGNOREIP
CONF
else
    warn "$F2B_JAIL_LOCAL exists — left untouched."
    warn "For a global whitelist, make sure its [DEFAULT] ignoreip includes:"
    warn "    $IGNOREIP"
fi

[[ -e /etc/fail2ban/action.d/nftables-allports.conf ]] || \
    warn "action 'nftables-allports' not found — your fail2ban may be too old."

# ── Start / reload fail2ban ─────────────────────────────────────────────
step "Starting fail2ban"
if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] would: systemctl enable --now fail2ban && fail2ban-client reload"
else
    run systemctl enable --now fail2ban
    if ! systemctl reload fail2ban 2>/dev/null && ! fail2ban-client reload 2>/dev/null; then
        run systemctl restart fail2ban
    fi
    ok "fail2ban running"
fi

# ── Summary ─────────────────────────────────────────────────────────────
step "Done"
if [[ $DRY_RUN -eq 1 ]]; then
    info "Dry run complete. Re-run without --dry-run to apply."
    exit 0
fi
cat <<DONE
  ${C_GRN}Honeypot is live.${C_0} Scanners hitting /.env, /.git, /wp-login.php… get
  one 404, their IP lands in $HONEYPOT_LOG, and fail2ban bans them on all ports.

  Whitelisted (won't be banned): ${C_B}$IGNOREIP${C_0}

  Check it:
    sudo fail2ban-client status nginx-honeypot
    sudo nft list table inet f2b-table
  Unban:
    sudo fail2ban-client set nginx-honeypot unbanip <IP>
    sudo fail2ban-client unban --all
DONE
fail2ban-client status nginx-honeypot 2>/dev/null || true
