# Переносимый Linux стенд кабинета

Пакет предназначен для локального тестирования входа, устройств, сохранённых pending-профилей, инструкций и read-only admin. Это ещё не готовый VPN: native/core/client acceptance, audited readiness transition и выдача рабочих профилей остаются открытыми. Cross-build не подтверждает выполнение на Linux. Production deployment, публичный listener и pilot acceptance этим пакетом не реализуются.

v0.28 дополнительно включает network-stand-runbook.md и trusted RU/network CLI. Они исполняются отдельно от HTTP UID, не открывают control DB/socket/root tools кабинету и не запускают cores. Native isolation/current client issuance/forwarding0 preservation ещё открыты.

v0.25 также включает trusted CLI диагностику selected-peer handshake/counters и `profile-awg-session-runbook.md`. Она требует уже существующего согласованного AWG стенда и encrypted pending client profile; обычный кабинетный init их не создаёт. Result всегда blocked, runtime/core/client/DNS/routing acceptance и выдача остаются открытыми.

v0.27 добавляет visual protocol/configuration status cards; connection/client остаются unknown до actual proof. Runbook protocol-status-runbook.md включён в runtime bundle. Footer показывает package version сборки. Для artifact delivery после ручного commit подготовлен GitHub prerelease/bootstrap из vpn-bootstrap-runbook.md; это не обновление/публикация работающего кабинета и не activation сети.

v0.26 включает root-only operator bootstrap ядер и отдельное private Foreign staging: `vpn-bootstrap-runbook.md`. Его запускать отдельно от portal/admin UID; этим HTTP процессам не выдавать root/ядра/staging. Bootstrap не запускает VPN/network/service и не меняет DB/readiness. Runtime bundle содержит `scripts/bootstrap-foreign.sh`, source SDK на VPS не нужен.

Стенд слушает только `https://127.0.0.1:8443` и `https://127.0.0.1:9443`. Открывать браузер на том же Linux компьютере. Использовать отдельные тестовые пароли. Не публиковать его через proxy/tunnel. Одно-UID локальный запуск не доказывает изоляцию production процессов.

## Собрать пакет на рабочем компьютере

Нужны версии Go/Node и зависимости из README. Сначала остановить browser tests, затем:

```sh
npm run check
npm run build
npm run test:persistence
npm run test:intents
npm run test:release
npm run test:e2e
npm run test:e2e:auth
npm run test:e2e:admin
npm run release:linux
```

Для ARM64: `npm run release:linux -- --arch arm64`. По умолчанию amd64. Builder использует уже собранный `web/dist`, не запускает Vite/E2E и не создаёт state/credentials. Поэтому сначала завершить проверки и сборку, затем упаковку; не менять исходники или `dist` между ними.

Если bundled Chromium недоступен, optional `FVPN_TEST_BROWSER=chrome` или `msedge` выбирает установленный browser channel только для тестов; unset использует pinned Playwright Chromium. Версию фактически использованного браузера фиксировать в отчёте. Unknown channel отклоняется. Полный auth/import/admin flow проверять на Linux: Windows key ownership намеренно fail-closed. Частичный Windows PASS не заменяет эти suites или race/native acceptance.

Архив и внешний SHA256 появляются в `build/releases/`. Внутри только три Linux binary, static frontend, интерактивный admin helper, эта инструкция, `release.json` и `SHA256SUMS`. Агент/controller/probe, state, keys, toolchain, dependencies и test outputs исключены. Уже существующий архив не перезаписывается. `release.json` сохраняет native/client/Linux/UID acceptance как false; тестовый отчёт хранить отдельно без credentials.

## Развернуть файлы на разрешённом локальном Linux стенде

Выбрать правильную архитектуру Linux. После переноса архива и соседнего `.sha256` проверить внешний SHA256, распаковать в новый каталог версии и проверить внутренние файлы:

```sh
sha256sum -c family-vpn-v<VERSION>-linux-amd64.tar.gz.sha256
tar -xzf family-vpn-v<VERSION>-linux-amd64.tar.gz
cd family-vpn-v<VERSION>-linux-amd64
sha256sum -c SHA256SUMS
```

Заменить `<VERSION>` фактической версией из имени архива, для ARM64 заменить архитектуру. Node, npm и Go на runtime стенде не нужны. Python 3 нужен только для необязательного интерактивного admin helper. Три binary должны иметь executable mode; библиотечные/native требования конкретного Linux подтвердить реальным запуском, не архивным hash.

State хранить отдельно от каталога версии. В следующих командах `../stand-state` — частный каталог рядом с версией; использовать свой выбранный путь последовательно. Создание/миграции выполнять при остановленных portal/admin. HTTP runtime не должен создавать master/profile keys.

```sh
umask 077
mkdir -p ../stand-state
./build/vpnctl auth-init --root ../stand-state/users
./build/vpnctl admin-key-create --root ../stand-state/admin --master-key ../stand-state/admin-secrets/master.key
./build/vpnctl admin-init --root ../stand-state/admin --master-key ../stand-state/admin-secrets/master.key
python3 scripts/admin-credentials.py enroll --login owner --root ../stand-state/admin --master-key ../stand-state/admin-secrets/master.key
python3 scripts/admin-credentials.py confirm --login owner --root ../stand-state/admin --master-key ../stand-state/admin-secrets/master.key
```

Helper скрывает пароль/код и передаёт его только в stdin CLI. Setup secret показать оператору один раз, вне логов/скриншотов; добавить в authenticator и подтвердить. Дождаться следующего TOTP step до browser login. `admin-key-create` выполнить только при первоначальном setup: повтор сохранит прежний ключ и завершится отказом. Ключ находится вне admin DB root, отдельную защищённую копию хранить отдельно от backup DB.

Для portal-only проверки пропустить admin setup и `--require-admin`. Проверить локальные файлы перед запуском:

```sh
./build/vpnctl stand-check --portal-root ../stand-state/users --admin-root ../stand-state/admin --master-key ../stand-state/admin-secrets/master.key --web-dir web/dist --require-admin
```

`stand-check` ничего не исправляет: он открывает DB в SQLite read-only mode, не выполняет migrations/state/audit/session writes, не подключается к VPN/tools/control DB и не делает профиль ready. SQLite может создавать/обслуживать WAL/SHM sidecars даже при `mode=ro`: `read_only:true` означает логический запрет записи данных, `sqlite_sidecars_possible:true` явно сообщает эту особенность. Не использовать `immutable=1` для живой WAL DB.

Проверяются identity/schema/local-auth dataset, TLS срок/SAN/key match/private key permissions, весь frontend tree и entry/mount/assets; с `--require-admin` — Linux, отдельные state/key paths, admin key decryptability и наличие подтверждённого MFA аккаунта. Это не проверка browser flow или пароль/TOTP session. `status:ok` относится к этим локальным условиям; `vpn_ready:false` и `profile_delivery_available:false` остаются false. При `blocked` сначала устранить указанную причину доверенным offline способом. Истёкший или неполный local TLS требует отдельного исправления до запуска; не сбрасывать DB/account ради сертификата и не отключать проверки ключа.

## Запустить и проверить restart

В первом терминале:

```sh
./build/portal --local-auth --listen 127.0.0.1:8443 --portal-db ../stand-state/users/portal/state.db --tls-cert ../stand-state/users/tls/local-cert.pem --tls-key ../stand-state/users/tls/local-key.pem --web-dir web/dist
```

Во втором:

```sh
./build/admin --local-auth --listen 127.0.0.1:9443 --portal-db ../stand-state/users/portal/state.db --admin-db ../stand-state/admin/auth/state.db --master-key ../stand-state/admin-secrets/master.key --tls-cert ../stand-state/admin/tls/local-cert.pem --tls-key ../stand-state/admin/tls/local-key.pem --web-dir web/dist
```

User portal открывает только user DB, admin получает user DB read-only и собственные credentials/key. Local certificate self-signed для loopback, срок первоначального сертификата 30 дней. Временное доверие браузера допустимо только для этих локальных test certificates; глобальную проверку TLS не отключать.

В третьем терминале создать приглашение:

```sh
./build/vpnctl auth-invite --root ../stand-state/users --login family-test --name "Тестовый пользователь"
```

Вставить token в форму приглашения на `https://127.0.0.1:8443`, задать тестовый пароль и создать устройство. Token не вставлять в URL/командный history/общий лог. На `https://127.0.0.1:9443` проверить password → TOTP → очередь/пользователи/безопасный аудит. Password-only admin не создаёт session.

Остановить процессы Ctrl+C, повторить `stand-check`, вновь запустить те же binary с теми же state paths. Проверить сохранённый аккаунт/устройство, повторный user login и admin MFA. Проверить logout и отказ прежней session. Для импортированных через отдельный trusted CLI pending-профилей проверить сохранённый статус и отсутствие download; этот пакет не выдаёт рабочие VPN-конфиги.

`/healthz` проверяет наличие HTTP процесса, `/readyz` — доступность user DB. Они не подтверждают admin auth, frontend, VPN или готовность профилей. Проверять пользовательский и admin flow отдельно, включая desktop/mobile и отказ чужому пользователю.

## Обновление, отказ и границы приёмки

Сохранить прежний каталог версии и private state. Остановить процессы, сделать согласованный private backup закрытых DB и необходимые отдельные защищённые копии ключей, сверить schemas release manifest. Из нового каталога выполнить явно нужные trusted migration CLI и `stand-check`, затем direct startup. В этой поставке schemas portal6/admin1; Control DB не нужна.

Не копировать работающий SQLite WAL как единственный backup. Проверенный backup/restore/reboot/rollback CLI ещё впереди; эту инструкцию нельзя считать его приёмкой. При неизменных schemas возможен запуск прежней версии с текущим state после остановки новой, но его фактическую совместимость проверить на отдельной копии. Backup rollback может воскресить sessions/replay counters; не восстанавливать старый auth state на действующем стенде без отдельной процедуры восстановления.

Для реального M1/G1 нужны разрешённый Linux VPN стенд, независимые tool/core/kernel/config/runtime pins и boot/netns/endpoint scope, actual peer/responder evidence, pinned VPN-клиенты с exact export/import/connect/handshake/DNS/routing и audited writer-fenced readiness transition. Затем owner delivery/QR и проверенный client guide. Для использования на действующих серверах дополнительно нужны management/TLS inputs, UID isolation, fail-closed, recovery/backup/upgrade и release/pilot gates. Этот пакет их не закрывает; VPS, SSH, routes и firewall из локальной разработки не меняются.
