# nginx-scanner-trap

[English](README.md) · **Русский**

Превращает сервер с nginx в ловушку для сканеров уязвимостей — и автоматически
банит их через **fail2ban + nftables**. Один скрипт, работает из коробки.

Боты круглосуточно прощупывают каждый публичный IP на `/.env`, `/.git/config`,
`/wp-login.php`, `/phpmyadmin`… Каждый такой запрос — безобидный 404, но в массе
это лишняя нагрузка и шум, за которым в алертах теряются настоящие 404.
`setup-honeypot.sh` делает так, что **первый** же такой запрос стоит боту доступа
ко всему хосту.

> Подробный разбор — зачем и как, шаг за шагом:
>
> - **English** — https://gistrec.cloud/blog/nginx-honeypot-fail2ban/
> - **Русский** — https://gistrec.cloud/blog/nginx-honeypot-fail2ban/ru/

## Что он делает

- Добавляет в nginx `log_format`, который пишет IP клиента, время и строку
  запроса (в http-контексте) — чтобы было видно, *что* именно прощупывали.
- `honeypot.conf` — пишет в отдельный лог обращения к путям, которые реальный
  клиент никогда не запрашивает (`/.env`, `/.git`, `/.aws`, `/.ssh`,
  `config.php.bak`, `backup.sql`), и возвращает 404. `wp-login.php`/`phpmyadmin`
  включаются отдельно через `--aggressive` (на хостах с WordPress/phpMyAdmin они
  могут быть легитимными).
- `deny-dotfiles.conf` — 404 на любые прочие dot-файлы, но оставляет рабочим
  `/.well-known/acme-challenge/`, чтобы не ломать продление сертификатов
  Let's Encrypt.
- Подключает оба сниппета в каждый `server { }` из `sites-enabled/`
  (идемпотентно; бэкапы — в `/var/backups/`, при ошибке `nginx -t` изменения
  откатываются).
- Устанавливает и настраивает **fail2ban**: фильтр для лога honeypot и jail
  (`maxretry=1`, `nftables-allports`, инкрементальные баны вплоть до недели) и
  проверяет, что jail действительно загрузился.
- **Автоматически определяет ваш IP** и спрашивает, какие ещё IP добавить в
  белый список — бан блокирует *все* порты (включая SSH), так что именно это не
  даёт вам заблокировать самого себя.

## Быстрый старт

> ⚠️ Скрипт работает от root и правит nginx + fail2ban. **Сначала прочитайте
> его** — никогда не отправляйте случайный скрипт в `sudo bash` вслепую.

Скачайте, прочитайте, запустите:

```bash
curl -fsSLO https://raw.githubusercontent.com/gistrec/nginx-scanner-trap/main/setup-honeypot.sh
less setup-honeypot.sh         # прочитать
sudo bash setup-honeypot.sh    # интерактивно: подтверждает ваш IP, спрашивает остальные
```

Перед чтением и запуском убедитесь, что скачанный файл совпадает с опубликованной
контрольной суммой (MD5 / SHA-256 текущего `main`):

```bash
md5sum setup-honeypot.sh
# ожидается: 6447f7bafd06922de5631ceb5238394e  setup-honeypot.sh

# или проверить в одну команду (выводит "setup-honeypot.sh: OK"):
echo "6447f7bafd06922de5631ceb5238394e  setup-honeypot.sh" | md5sum -c -

# SHA-256 (надёжнее):
sha256sum setup-honeypot.sh
# ожидается: 0cd029a738716f7b4b988125c54451c9fe78c9d8d63ac525ee0e018469a9ef0b  setup-honeypot.sh
```

> Контрольные суммы привязаны к текущему `main` и меняются вместе со скриптом.
> Хеш из того же репозитория ловит только повреждение при передаче, но не подмену
> самого репозитория — поэтому всё равно прочитайте скрипт перед запуском.

Предпросмотр без каких-либо изменений:

```bash
sudo bash setup-honeypot.sh --dry-run
```

Однострочник (только если доверяете):

```bash
curl -fsSL https://raw.githubusercontent.com/gistrec/nginx-scanner-trap/main/setup-honeypot.sh | sudo bash
```

## Опции

| флаг | значение |
|------|----------|
| `--ip <ip>` | ваш админский IP (пропустить автоопределение) |
| `--extra "<ips>"` | дополнительные IP/CIDR в белый список (через пробел) |
| `--aggressive` | также ловить `wp-login.php` / `phpmyadmin` / `xmlrpc.php` (не для хостов с WordPress/phpMyAdmin) |
| `--no-wire` | не трогать `sites-enabled`; вместо этого вывести строки include |
| `--allow-no-whitelist` | продолжить, даже если в белый список не попал ни один админский IP (рискованно) |
| `--bantime <spec>` | базовое время бана (по умолчанию `86400`; принимает `1h`/`1d`/`1w`) |
| `--maxtime <spec>` | максимальный инкрементальный бан (по умолчанию `1w`) |
| `-y, --yes` | отвечать «да» на все вопросы, без подтверждений |
| `--dry-run` | показать, что будет сделано, ничего не меняя |

## Безопасность

- **Идемпотентность** — повторный запуск не задублирует include; управляемые
  файлы перезаписываются на месте.
- **Бэкапы вне nginx** — каждый затронутый файл копируется в
  `/var/backups/nginx-scanner-trap/<timestamp>/` (не рядом с конфигом, где
  `include sites-enabled/*` иначе подхватил бы случайный `.bak`).
- **`nginx -t` с откатом** — если подключение ломает конфиг, все созданные или
  изменённые за запуск файлы автоматически откатываются, и скрипт прерывается.
- **Не заблокирует вас** — ваш IP (определяется через `SSH_CONNECTION` →
  `who am i` → `ss`) плюс всё, что вы добавите, причём `127.0.0.1/8 ::1` всегда в
  списке; без белого списка скрипт откажется запускаться, если не передать
  `--allow-no-whitelist`.
- Задаёт только `ignoreip` в `[DEFAULT]` файла `jail.local` (никак не меняет
  логику банов других jail, например `sshd`) и не трогает уже существующий
  `jail.local`.

## Требования

Debian/Ubuntu, уже установленный nginx, root. `fail2ban` и `nftables` скрипт
ставит сам, если их нет.

## За CDN / обратным прокси

Если nginx стоит за Cloudflare или любым обратным прокси, настройте
[`real_ip`](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
(`set_real_ip_from` + `real_ip_header`) **до** включения ловушки — иначе
`$remote_addr` будет IP прокси, и fail2ban забанит ваш прокси/CDN, а не сканер.

## Проверка / разбан

```bash
sudo fail2ban-client status nginx-honeypot
sudo nft list table inet f2b-table
sudo fail2ban-client set nginx-honeypot unbanip <IP>   # один IP
sudo fail2ban-client unban --all                       # всё
```

## Лицензия

[MIT](LICENSE) © Aleksandr Kovalko
