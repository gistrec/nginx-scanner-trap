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

- Adds an nginx `log_format` that writes **just the client IP** (http context).
- `honeypot.conf` — logs probes of sensitive paths (`/.env`, `/.git`, `/.aws`,
  `/.ssh`, `wp-login.php`, `phpmyadmin`, …) to a dedicated log and returns 404.
- `deny-dotfiles.conf` — 404 for any other dotfile, kept out of the trap.
- Wires both snippets into every `server { }` in `sites-enabled/`
  (idempotent, each file backed up first).
- Installs and configures **fail2ban**: a filter for the IP-only log and a jail
  (`maxretry=1`, `nftables-allports`, incremental bans up to a week).
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
| `--no-wire` | don't touch `sites-enabled`; print the include lines instead |
| `--bantime <sec>` | base ban time (default `86400` = 24h) |
| `--maxtime <spec>` | max incremental ban (default `1w`) |
| `-y, --yes` | assume yes, no prompts |
| `--dry-run` | show what would happen, change nothing |

## Safety

- **Idempotent** — re-running won't duplicate includes; managed files are
  rewritten in place.
- **Backups** — every file it edits is copied to `*.bak.<timestamp>` first.
- **`nginx -t` with rollback** — if wiring the snippets breaks the config, the
  site edits are reverted automatically and the script aborts.
- **Whitelist first** — your IP (auto-detected via `SSH_CONNECTION` →
  `who am i` → `ss`) plus anything you add, with `127.0.0.1/8 ::1` always in.
- Leaves an existing `/etc/fail2ban/jail.local` untouched.

## Requirements

Debian/Ubuntu, nginx already installed, root. `fail2ban` and `nftables` are
installed by the script if missing.

## Check / unban

```bash
sudo fail2ban-client status nginx-honeypot
sudo nft list table inet f2b-table
sudo fail2ban-client set nginx-honeypot unbanip <IP>   # one IP
sudo fail2ban-client unban --all                       # everything
```

## License

[MIT](LICENSE) © Aleksandr Kovalko
