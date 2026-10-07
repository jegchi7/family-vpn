# Локальный admin MFA · v0.5.0

Linux, отдельный тестовый пароль и authenticator. Go/Node требования как в README. Python 3 нужен только для интерактивного wrapper. Настоящие серверы/маршрутизация здесь не настраиваются. Windows admin key loading намеренно закрыт до реализации ACL validation; macOS не проверялся.

## Первый запуск

Из корня проекта после `npm run setup && npm run build`:

```sh
./build/vpnctl admin-key-create
./build/vpnctl admin-init
python3 scripts/admin-credentials.py enroll --login owner
```

Ключ создаётся в `var/admin-secrets/master.key`, админская БД — `var/admin/auth/state.db`. Ключ никогда автоматически не перевыпускается. Существующий key-create завершится отказом и сохранит прежний ключ. Его резервная копия должна быть отдельно от backup DB, с private permissions; не добавлять весь `var/` в общий backup или Git.

Wrapper скрыто спросит пароль и повтор. CLI покажет JSON с новым `secret`: вручную добавить в приложение-аутентификатор как time-based OTP, 6 цифр / SHA1 / 30 секунд. Issuer `Family VPN Admin`, account `owner`. Этот secret даёт возможность генерировать коды: не отправлять его в чат, тикет или общий лог. Экспорт OTP в QR/URL пока не реализован.

В течение 10 минут:

```sh
python3 scripts/admin-credentials.py confirm --login owner
npm run admin
```

Ввести текущий код authenticator, затем **дождаться следующего кода**, поскольку подтверждённый step уже использован. Открыть **https://127.0.0.1:9443**, пройти пароль → TOTP. Первые password-only credentials не создают сессию. Локальный self-signed сертификат предназначен только для стенда; не переносить этот способ доверия на реальные домены. Отдельная инструкция для клиента остаётся в `auth-runbook.md` (`npm run auth`, порт 8443).

`npm run admin` открывает пользовательскую БД read-only для счётчика/статуса. Если `var/auth` ещё не инициализирован, запускает `auth-init`; существующие accounts сохраняются. Admin store migration выполняется через trusted `admin-init`; HTTP runtime схемы не меняет. Master key должен быть создан заранее. Dashboard только читает данные: реальные устройства/конфиги/управление узлами не реализованы.

Пароль/код также можно передать непосредственно в stdin `vpnctl admin-enroll`, `admin-reset`, `admin-confirm` в одном JSON объекте с полем `password` или `code`. Не передавать секреты через arguments, environment или литералы shell history. Не включать trace запросов с credentials. Wrapper — рекомендуемый ручной способ.

## Если настройка не завершена или authenticator потерян

```sh
python3 scripts/admin-credentials.py reset --login owner
python3 scripts/admin-credentials.py confirm --login owner
```

`reset` **сразу** отключает прежний пароль/TOTP и все admin sessions/challenges, выдаёт новый setup secret и требует нового подтверждения. Admin ID сохраняется, клиентские accounts/VPN profiles не затрагиваются. Если enrollment истёк или setup secret потерян, тоже использовать reset, а не повторный enroll существующего login.

Немедленно отключить admin без выдачи нового доступа:

```sh
./build/vpnctl admin-disable --login owner
```

Работает и при отсутствующем master key. Для повторного включения требуется reset + confirm. Отзыв применяется к следующим requests; уже начавшийся read-only GET не отменяется задним числом.

Если потерян master key: остановить admin process, восстановить private key из отдельной защищённой копии и проверить доступ. При отсутствии копии действующие TOTP невозможно расшифровать. Trusted console может disable каждый существующий admin, создать **новый отдельный** key path через admin-key-create и reset + confirm с `--master-key` для каждого аккаунта. Не удалять/подменять key в работающем процессе; новый runtime нужно запускать с тем же явным path. Backup rollback также может вернуть старые sessions/replay counters — безопасное восстановление всего контура пока не автоматизировано и является незакрытой задачей.

## Политики и диагностика

- TOTP challenge: 3 минуты, 5 попыток; новый password login заменяет прежний challenge этого аккаунта. Login limiter 5/5min на account, 30/5min на socket IP; параметры не брать из X-Forwarded-For.
- Сессия: 12 часов максимум, 30 минут idle. Видимая страница отправляет touch раз в 5 минут. Выход очищает cookie и отзывает серверную сессию. Пароль и OTP не остаются в форме после отправки; challenge/CSRF только в памяти JS.
- После смены вкладки/обновления preauth bootstrap прежний challenge может не подходить по cookie binding: начать вход заново. После 5 ошибок подождать 5 минут. Проверить часы сервера/телефона.
- Key file 0600 и его родитель 0700, принадлежит UID процесса; symlink запрещены. Не исправлять эти проверки отключением TLS, CSRF или key validation.
- Admin DB имеет собственный application_id: передача её в `--portal-db` запрещена. Control DB и agent socket не открываются ни одним HTTP-процессом.

## Проверки

`npm run check`, `npm run build`, `npm run test:persistence`, `npm run test:e2e`, `npm run test:e2e:auth`, `npm run test:e2e:admin`.

Admin E2E создаёт отдельные временные state и master key. Для теста используется предыдущий TOTP step при confirm, текущий — при login, в пределах нормального ±1 окна; production clocks не подменяются. Browser errors/traces могут включать временные test credentials: не публиковать output directories. Screenshots из поставки сняты только с пустыми секретными полями. При завершении локальных E2E временные каталоги остаются для диагностики; удалять только созданные тестом пути после остановки процессов.

Recovery codes, passkey, fresh authentication, runtime UID isolation и production origin/certificate ещё не готовы. G0/G1 и остальные gates не закрыты.
