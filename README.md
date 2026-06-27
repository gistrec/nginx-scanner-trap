# nginx-scanner-trap

Turn an nginx box into a honeypot for vulnerability scanners — and ban them
automatically with **fail2ban + nftables**. One script, works out of the box.

Bots probe every public IP for `/.env`, `/.git/config`, `/wp-login.php`,
`/phpmyadmin`… around the clock. Each is a harmless 404, but in bulk it's
wasted load and noise that buries real 404s in your alerts. `setup-honeypot.sh`
makes the **first** such request cost the bot its access to the whole host.

> Full write-up — the why and the how, step by step:
> · **English** — https://gistrec.cloud/blog/nginx-honeypot-fail2ban/
> · **Русский** — https://gistrec.cloud/blog/nginx-honeypot-fail2ban/ru/

## What it does

- Adds an nginx `log_format` that records the client IP, timestamp, and the
  probed request line (http context) — so you can see *what* was hit.
- `honeypot.conf` — logs probes of paths a real client never requests (`/.env`,
  `/.git`, `/.aws`, `/.ssh`, `config.php.bak`, `backup.sql`) to a dedicated log
  and returns 404. `wp-login.php`/`phpmyadmin` are opt-in via `--aggressive`
  (they can be legitimate on WordPress/phpMyAdmin hosts).
- `deny-dotfiles.conf` — 404 for any other dotfile, but keeps
  `/.well-known/acme-challenge/` working so Let's Encrypt renewals don't break.
- Wires both snippets into every `server { }` in `sites-enabled/` (idempotent;
  backups go to `/var/backups/`, with an `nginx -t` rollback on failure).
- Installs and configures **fail2ban**: a filter for the honeypot log and a jail
  (`maxretry=1`, `nftables-allports`, incremental bans up to a week), and
  verifies the jail actually loaded.
- **Auto-detects your IP** and asks for any extra IPs to whitelist — the ban
  blocks *all* ports (SSH included), so this is what stops you locking yourself
  out.

## Quick start

> ⚠️ It runs as root and edits nginx + fail2ban. **Read it first** — never pipe
> a random script into `sudo bash` blind.

Download, read, run:

```bash
curl -fsSLO https://raw.githubusercontent.com/gistrec/nginx-scanner-trap/main/setup-honeypot.sh
less setup-honeypot.sh         # read it
sudo bash setup-honeypot.sh    # interactive: confirms your IP, asks for extras
```

Preview without changing anything:

```bash
sudo bash setup-honeypot.sh --dry-run
```

One-liner (only if you trust it):

```bash
curl -fsSL https://raw.githubusercontent.com/gistrec/nginx-scanner-trap/main/setup-honeypot.sh | sudo bash
```

## Options

| flag | meaning |
|------|---------|
| `--ip <ip>` | your admin IP (skip auto-detection) |
| `--extra "<ips>"` | extra IPs/CIDRs to whitelist (space-separated) |
| `--aggressive` | also trap `wp-login.php` / `phpmyadmin` / `xmlrpc.php` (not for WordPress/phpMyAdmin hosts) |
| `--no-wire` | don't touch `sites-enabled`; print the include lines instead |
| `--allow-no-whitelist` | proceed even if no admin IP gets whitelisted (risky) |
| `--bantime <spec>` | base ban time (default `86400`; accepts `1h`/`1d`/`1w`) |
| `--maxtime <spec>` | max incremental ban (default `1w`) |
| `-y, --yes` | assume yes, no prompts |
| `--dry-run` | show what would happen, change nothing |

## Safety

- **Idempotent** — re-running won't duplicate includes; managed files are
  rewritten in place.
- **Backups outside nginx** — every file it touches is copied under
  `/var/backups/nginx-scanner-trap/<timestamp>/` (not next to the config, where
  `include sites-enabled/*` would otherwise load a stray `.bak`).
- **`nginx -t` with rollback** — if wiring breaks the config, every file the run
  created or modified is reverted automatically and the script aborts.
- **Won't lock you out** — your IP (auto-detected via `SSH_CONNECTION` →
  `who am i` → `ss`) plus anything you add, with `127.0.0.1/8 ::1` always in; it
  refuses to run with no whitelist unless you pass `--allow-no-whitelist`.
- Sets only `ignoreip` in `jail.local` `[DEFAULT]` (never changes how other
  jails such as `sshd` ban), and leaves an existing `jail.local` untouched.

## Requirements

Debian/Ubuntu, nginx already installed, root. `fail2ban` and `nftables` are
installed by the script if missing.

## Behind a CDN / reverse proxy

If nginx sits behind Cloudflare or any reverse proxy, configure
[`real_ip`](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
(`set_real_ip_from` + `real_ip_header`) **before** enabling the trap — otherwise
`$remote_addr` is the proxy's IP and fail2ban will ban your proxy/CDN, not the
scanner.

## Check / unban

```bash
sudo fail2ban-client status nginx-honeypot
sudo nft list table inet f2b-table
sudo fail2ban-client set nginx-honeypot unbanip <IP>   # one IP
sudo fail2ban-client unban --all                       # everything
```

## License

[MIT](LICENSE) © Aleksandr Kovalko
