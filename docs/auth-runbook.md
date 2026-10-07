# Локальный стенд входа · v0.5.0

Это пользовательская авторизация для разработки на одном компьютере. Требуется HTTPS; не публиковать стенд через reverse proxy/tunnel. Использовать отдельные тестовые пароли. Для реальных пользователей сначала завершить DEV-05, QA и deployment gates.

## Запуск

Из корня проекта:

```sh
npm run setup
npm run build
npm run auth
```

Runner создаёт `var/auth/portal/state.db`, отдельный от `var/demo`, и self-signed certificate на 30 дней для loopback. Открыть **https://127.0.0.1:8443**. Для этого конкретного локального адреса браузер покажет предупреждение о self-signed сертификате; временное исключение допустимо только на локальном тестовом стенде. Не отключать проверку сертификатов глобально и не устанавливать этот ключ/сертификат на VPS.

Во втором терминале создать пользователя и одноразовое приглашение:

```sh
./build/vpnctl auth-invite --login family-test --name "Тестовый пользователь"
```

В PowerShell: `./build/vpnctl.exe auth-invite --login family-test --name "Тестовый пользователь"`.

Команда выводит JSON с token. В кабинете нажать «У меня приглашение», вставить только значение token, задать и подтвердить пароль (минимум 12 символов). Код действует 24 часа; можно ограничить `--invite-ttl 1h`. Он не входит в URL, не должен попадать в общий лог/скриншот/репозиторий. Команда не отправляет приглашение никому сама.

После активации появится пустой кабинет. Reload и перезапуск сервера сохраняют аккаунт и browser session. «Выйти» отзывает текущую сессию; повторный вход — по login и password. Повторная активация старого приглашения отклоняется. Создание устройств, выдача VPN-конфигов и passkey пока не реализованы. Отдельный admin MFA listener описан в `admin-auth-runbook.md`. Повторный `auth-invite` для занятого login возвращает конфликт, а не меняет пароль.

## Режимы и данные

- `npm run demo`: прежний HTTP read-only экран на :8080/:8081, фиксированные fixtures, БД `var/demo`.
- `npm run auth`: пользовательский HTTPS кабинет :8443, отдельная БД `var/auth`, нет admin listener.
- `vpnctl auth-init --root <path>`: миграции и отдельный локальный TLS certificate. Повтор не сбрасывает аккаунты или ключи. Миграции перед обновлением выполнять с остановленным сервисом.
- Для ручного запуска `portal --local-auth` обязательны `--portal-db`, `--tls-cert`, `--tls-key` своего root; использовать `--listen 127.0.0.1:8443`.
- HTTP startup не создаёт и не мигрирует auth DB. Wrong dataset, старая/чужая/повреждённая схема останавливают старт.
- Если сертификат истёк/повреждён, простейший безопасный тестовый reset — новый `--root`; прежние файлы сохранить. Автоматического удаления данных или rotation CLI пока нет.

Session TTL: `--session-ttl 720h --session-idle 168h` по умолчанию. Для короткой ручной проверки использовать, например, `--session-ttl 10m --session-idle 2m`. UI touch каждые 5 минут работает только при видимой вкладке; GET API не продлевает idle.

## Проверки

```sh
npm run check
npm run build
npm run test:persistence
npm --prefix web exec -- playwright install chromium
npm run test:e2e
npm run test:e2e:auth
```

Перед браузерными тестами остановить запущенные local demo/auth. Auth E2E использует отдельный временный каталог на каждый запуск, случайные login/password/invite, проверяет активацию, reload, logout, login и повтор приглашения на desktop/mobile. Self-signed verification bypass находится только в test config; приложение не отключает TLS verification клиентов. Не сохранять auth traces или screenshots с заполненными секретами.

На Windows/macOS запуск этой поставки не проверялся; POSIX permissions не заменяют Windows ACL. Production UID isolation, реальный домен/RP ID и реальные VPN-устройства этой инструкцией не проверяются.

## Восстановление и новый invite

В v0.4.0 работают `auth-recovery` для active password-only user и `auth-reissue-invite` для invited user. Обязательные последствия и шаги: `recovery-runbook.md`. Это не восстановление admin/MFA/passkey.
