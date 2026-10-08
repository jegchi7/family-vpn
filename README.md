# Family VPN · итерация 28 · v0.28.0

v0.28 добавляет private RU REALITY ingress через loopback SOCKS/relay sing-box на Foreign и закрытый IPv4 `vpn-data` kernel guard. Trusted `network-plan/prepare/apply/check` отделены от HTTP и требуют независимых helper pins/boot/netns/topology; применение читает установленные правила до activation и сохраняет защиту при ошибке. Cores автоматически не запускаются, клиентская привязка/выдача и Linux/Android acceptance ещё открыты. При выключенном host forwarding apply блокируется до изменения сети. Инструкция: `docs/network-stand-runbook.md`; отчёт: `docs/iteration-28.md`. Это локальная реализация, не проверенный deploy.

v0.27 согласует версии генераторов с pinned VPN cores и добавляет безопасные карточки состояния протоколов в ЛК и админку: конфигурация/сверка/TTL отдельно от подключения и клиента. HTTP читает только portal metadata; новых probes, ключей или control/socket доступа нет. Live connection пока «Нет данных». Добавлены commit-bound GitHub prerelease build и root bootstrap для RU/Foreign без Go/Node на VPS; после ручного commit владельца требуется зелёный Actions run. Ни одно ядро/сервис/сеть автоматически не активируется. Отчёт `docs/iteration-27.md`; статусы `docs/protocol-status-runbook.md`; команды `docs/vpn-bootstrap-runbook.md`. M1/G1 и реальный Android→RU→Foreign round-trip открыты.

v0.26 добавляет operator-run установку закреплённых Xray/sing-box/Hysteria binaries и private Foreign REALITY staging: `core-plan`, `core-install`, `core-status`, `foreign-init/check/status`. По умолчанию dry-run; установка/генерация только Linux root `--apply`. Из runtime bundle: `sudo ./scripts/bootstrap-foreign.sh --apply`. Инструкция: `docs/vpn-bootstrap-runbook.md`; результаты и ограничения: `docs/iteration-26.md`. Ядра не запускаются, сеть не меняется, AWG install и реальный Android→RU→Foreign путь пока не приняты. Рабочая выдача VPN и acceptance M1/G1 ещё открыты. Существующая AWG session диагностика сохранена: `docs/profile-awg-session-runbook.md`. Комплект кабинета: `npm run release:linux`, `docs/stand-runbook.md`.

Go + Svelte кабинет с SQLite и работающим **локальным пользовательским входом**: одноразовое приглашение → пароль → серверная сессия → свои устройства. Пользователь может создать заявку на устройство, выбрать ОС, переименовать и отменить её до выдачи доступа. Квоты и данные сохраняются в SQLite. Одноразовое восстановление через trusted CLI и перевыпуск приглашений также работают. Добавлен отдельный локальный вход администратора по паролю и TOTP. Есть зашифрованное хранилище клиентских профилей и trusted CLI ключей. Добавлен trusted CLI импорта ограниченного VLESS/REALITY URI с dry-run/apply. Добавлены versioned инструкции кабинета для шести вариантов ОС и скачиваемые автономные HTML-памятки. Совместимость VPN-клиентов пока помечена draft. Выдача рабочих VPN-конфигов, passkey, recovery codes, обмен шлюзов и production deploy пока не реализованы. Есть отдельный synthetic agent/queue stand: это проверка метаданных, не управление VPN.

## Запуск дома

Go **1.27.1**, Node **24.19.0**, npm 11.9.0. Frontend packages закреплены lockfile, Go dependencies — go.mod/go.sum. Первые setup/build требуют доступа к npm и Go module proxy. Сборка выполняется на ПК/CI, не RU VPS 2 ГБ.

```sh
npm run setup
npm run build
npm run auth
```

Открыть **https://127.0.0.1:8443**. Это локальный self-signed test certificate; браузер покажет предупреждение. Для этого стенда использовать отдельный тестовый пароль. Подробности и ограничения сертификата: `docs/auth-runbook.md`.

Во втором терминале:

```sh
./build/vpnctl auth-invite --login family-test --name "Тестовый пользователь"
```

Windows PowerShell: executable `./build/vpnctl.exe`. Скопировать token из результата в форму «У меня приглашение». Token одноразовый, действует 24 часа; не вставлять его в адресную строку и не сохранять в общий лог. После активации работают reload, logout и повторный password login. Никаких сообщений CLI сам не отправляет.

## Устройства

В кабинете нажать «Добавить устройство», выбрать название и ОС. Заявка сохраняется с двумя ожидающими профилями AWG/REALITY. По умолчанию 5 слотов; повтор отправки не создаёт дубль. Переименование защищено от перезаписи изменений из другой вкладки. Отменить можно только ещё не выданную заявку.

Рабочие VPN-конфиги пока не выдаются: следующий этап — сверка установленного доступа и выдача. Сценарии заявок и прежний upgrade portal v3→v4: `docs/device-requests-runbook.md`.

## Зашифрованное хранилище профилей

После создания user state через `npm run auth` (затем остановить стенд) на Linux:

```sh
./build/vpnctl profile-key-create
./build/vpnctl profile-vault-init
./build/vpnctl profile-vault-check
```

Ключ `var/profile-secrets/current.key` находится вне `var/auth`; команда его создания не перезаписывает файл и не печатает ключ. База хранит только ciphertext/nonce/key ID. Ротация использует отдельный новый ключ и одну транзакцию; прежний ключ сохраняется. Полные команды, обновление portal v4→v5 и ограничения: `docs/profile-vault-runbook.md`.

DEV-07 реализован локально. Для DEV-08 есть `profile-targets --login family-test` и `profile-import`: по умолчанию read-only dry-run, запись только с `--apply`. Поддерживаются ограниченные `vless-reality-uri` и `awg-3.1-conf`; конфиг приходит из private file или stdin, не аргументом команды. Повтор не перезаписывает данные, один UUID/AWG client key нельзя присвоить двум профилям. Инструкция: `docs/profile-import-runbook.md`, матрица: `docs/client-format-matrix.md`.

Добавлен `profile-preflight`: read-only сверка с private Xray JSON snapshot, explicit inbound/endpoint и независимым SHA-256 pin. CLI вычисляет public key из server private key в памяти; серверный config не попадает в portal DB. Совпадение конфигурации не подтверждает running core/client. Инструкция: `docs/profile-preflight-runbook.md`.

Импорт остаётся pending до сверки actual peer. В кабинете видно «Сохранён, ждёт сверки»; скачать его пока нельзя. AWG3.1 .conf принимается в документированном client-only subset с сохранением новых полей. `vpn://`, другие транспорты и расширения ещё не принимаются. Сохранение в хранилище не означает установленный VPN-доступ.

## Инструкции и офлайн-памятка

После входа открыть «Как подключиться», выбрать ОС и нажать «Скачать офлайн-памятку». HTML открывается локально без интернета; в нём нет ключей, адреса панели или персональных данных. Версия и scope проверки показаны явно. Проверка сценария кабинета не означает compatibility VPN-приложения: AWG/REALITY client guides остаются draft, установка/deep links пока не предлагаются. Каталог встроен в binary, HTTP не редактирует его и не загружает из внешнего источника. `docs/guides-runbook.md`.

## Администратор: пароль + TOTP

Для Linux после сборки:

```sh
./build/vpnctl admin-key-create
./build/vpnctl admin-init
python3 scripts/admin-credentials.py enroll --login owner
```

Добавить выданный secret в authenticator, затем `python3 scripts/admin-credentials.py confirm --login owner`. Дождаться следующего кода и запустить `npm run admin`: **https://127.0.0.1:9443**. Интерактивный helper требует Python 3 и скрывает ввод; stdin JSON CLI доступен без Python.

Собственная admin DB, master key вне DB root, подтверждённый TOTP до активации; password-only session не выдаётся. Сессия 12h absolute / 30m idle, отдельные cookies. Dashboard read-only: очередь заявок/устройств, пользователи со статусами приглашений/восстановления и безопасный журнал действий. Страницы по 25 записей, фильтр состояния, обновление и переход дальше. Секреты/конфиги в интерфейс не попадают. Справка: `docs/admin-views-runbook.md`. `admin-reset`/`admin-disable` сразу отзывают сессии и pending challenges. Подробная настройка, восстановление, ограничения ОС и ключа: `docs/admin-auth-runbook.md`.

## Восстановление доступа

Для активного обычного пользователя: `./build/vpnctl auth-recovery --login family-test`. Команда **сразу отключает прежний пароль и все сессии кабинета**; одноразовый код действует 15 минут. В интерфейсе выбрать «Забыли пароль?», задать новый пароль, затем войти обычным способом. VPN-профили не меняются.

Для ещё не активированного пользователя: `./build/vpnctl auth-reissue-invite --login family-test`. Прежнее приглашение отзывается. Подробности и обновление с v0.3: `docs/recovery-runbook.md`.

## Демонстрация интерфейса

`npm run demo` сохраняет прежний read-only режим: **http://127.0.0.1:8080** — кабинет, **http://127.0.0.1:8081** — admin prototype. Здесь фиктивный пользователь и устройства, download — текстовая памятка, не VPN-конфиг. Health samples устаревают через 60 секунд; restart не обновляет их timestamps. Только numeric loopback, не `localhost`.

БД режимов раздельны: `var/demo` и `var/auth`; переключением флага нельзя выдать demo за аутентификацию. Оба режима запрещают публичный bind. Admin из demo не является защищённой админкой; защищённый local-admin использует отдельные `var/admin` и `var/admin-secrets`, порт 9443. Control DB ни один HTTP процесс не открывает.

## Проверки

```sh
npm run check
npm run build
npm run test:persistence
npm run test:intents
npm --prefix web exec -- playwright install chromium
npm run test:e2e
npm run test:e2e:auth
npm run test:e2e:admin
```

`check`: Go vet/race tests, API generation drift, Svelte typecheck, Vite build. Race требует C toolchain. Перед E2E остановить demo/auth: тесты поднимают сервисы сами. Auth E2E использует отдельный временный каталог на каждый запуск. Runtime зависимости, БД, секреты, TLS keys и executables в архив не входят.

## Документация и структура

- `docs/iteration-28.md`: выполненное и проверки; `docs/vpn-platform-backlog-v1.0.md` — единый актуальный реестр статусов.
- `docs/auth-runbook.md`: пошаговый локальный вход; `docs/storage-runbook.md`: прежний persistence demo.
- `docs/next-iteration.md`: ближайшие задачи; усиления auth отложены по решению владельца, приоритет — устройства/конфиги.
- `internal/auth`, `internal/adminauth`, `internal/store`, `internal/httpapi`: password/session logic, SQL transactions, HTTP boundary.
- `cmd/vpnctl`: local init/invite/recovery/reissue, admin key/enroll/confirm/reset/disable, demo init/status/rename. `cmd/portal` и `cmd/admin` — отдельные процессы.
- `api/openapi.json`: реализованный local subset и generated TS; `planned-auth.openapi.json` — оставшиеся будущие flows.
- `docs/gateway-backlog.md`: GW-01…08 по автоматической связке серверов; пока проектирование.
- `node-agent`, `hop-controller`: opt-in synthetic queue stand; default fail-fast, no VPN writes/hop selection. `foreign-probe` — placeholder.

Production запуск, настоящая выдача доступа и управление серверами не готовы. Текущий backlog обновлён внутри основного файла; baseline specification сохранена, изменения приоритетов записаны в ADR-0007. Linux local tests не доказывают изоляцию разными service UID или Windows ACL. Windows/macOS и реальные мобильные VPN-клиенты не проверены. Admin MFA на Windows намеренно закрыт до проверки ACL; подтверждён Linux local run. G0/G1 и последующие gates остаются открыты.

Архив не содержит .git/remote; загрузить в Git можно позже. Не добавлять `var/` и свои credentials. Лицензия владельцем пока не выбрана.

## Очередь и ограниченный агент

v0.12: durable intents в private control DB, idempotency/request hash, optimistic node revision, serialization, revoke priority, lease/attempt fencing и reconcile после потери ответа. Explicit `--fake-stand` для controller/agent; ни один HTTP process не получил control/socket доступ. Linux Unix transport написан, но AF_UNIX запрещён текущей средой (EPERM): его tests отмечены SKIP, required native acceptance ещё впереди. In-process tests не заменяют production UID/network tests. Команды и ограничения: `docs/intent-stand-runbook.md`; решение: ADR-0010. Схемы portal/control/admin5/3/1.

Проверки v0.12: Go/check/build/persistence/intent CLI прошли; два Unix tests skipped (AF_UNIX EPERM), browser E2E не выполнился из-за Chromium startup SIGSEGV. UI source unchanged v0.11. Точная запись ограничений и required acceptance — `docs/iteration-14.md`.

## Worker и управление очередью

v0.13: `hop-controller --fake-stand --command worker` выполняет очередь в foreground; delays2..60s сохраняются в DB, Ctrl+C/SIGTERM не теряет intent. `list` показывает safe metadata/state/next attempt, `cancel` отменяет только ещё не начатый Ensure; Revoke отменить нельзя. Cancellation заявки/операции не означает network revoke. Схемы5/4/1, explicit init upgrades stand control3→4. Runbook и ADR-0011 описывают запуск. UI source не менялся; native transport и Chromium ограничения сохраняются.

## Ближайшая цель M1/G1

Текущий фокус — ручная выдача рабочих профилей: импорт → подтверждение установленного доступа и клиента → owner download/QR → полный сценарий кабинета. План: `docs/milestone-m1.md`. v0.14 закрывает локальный AWG client parser/import/storage round-trip; native VPN client compatibility не проверена. Новых миграций нет (portal/control/admin5/4/1).

Go/race/check/build/persistence/intent CLI PASS, AWG fuzz197073 runs PASS. Chromium --version SIGSEGV, два AF_UNIX tests SKIP/EPERM; AWG E2E добавлены, discovery PASS, execution не выполнен. UI source не менялся; старые screenshots — история. Точный отчёт: `docs/iteration-14.md`. M1/G1 остаётся открытым.

## AWG readback и связанный результат

v0.15: trusted Linux `profile-observe-awg` читает существующий интерфейс через independently pinned `/usr/bin/awg`, сравнивает два readbacks и client peer/server/port/shared parameters/addresses. Default read-only; apply записывает только immutable scoped metadata/audit с TTL60s, не меняет ready/installed_revision/network. Native positive path и client round-trip ещё не проверены. Команды и upgrade portal5→6: `docs/profile-observation-runbook.md`. Текущие схемы portal/control/admin6/4/1.

M1-02 частично реализован; следующий срез — native/client acceptance, Xray runtime и отдельный readiness contract. Check/build/persistence/intents/race/fuzz прошли; UI source не менялся, новые browser проверки не запускались. Report: `docs/iteration-15.md`; canonical backlog1.10. Linear plugin установлен, но его действия недоступны в текущей сессии: `docs/linear-sync-plan.md` содержит черновик пяти карточек, внешняя синхронизация ещё не выполнена.

## Проверка перед выдачей

v0.16: `profile-readiness` даёт keyless read-only report current target и причины блокировки. Проверяются owner/device/generation/revision, последняя observation metadata, TTL60s, stale/future/conflict/snapshot scope; старое совпадение не скрывает свежий conflict. Команда не загружает ключ или client bytes и не выполняет readiness transition. Ready/client/secret verification false; diagnostic report имеет status:blocked и exit1. Runbook: `docs/profile-readiness-runbook.md`; report: `docs/iteration-16.md`. Схемы6/4/1 без миграции.

Current задачи ведутся в [Linear «Впн»](https://linear.app/kukin/project/vpn-d7991a20e59b), следующий срез [KUK-5](https://linear.app/kukin/issue/KUK-5/dev-08-m1-02-confirm-installed-access-flow-end-to-end). Это заменяет прежнюю запись о недоступности Linear в историческом абзаце v0.15. Canonical snapshot1.23 сохраняет оригинальные63 criteria; v0.28 обновлён локально, последний проверенный online sync относится к v0.23. KUK-5 In Progress, native/client/readiness transition и G1 открыты; KUK-6/7 delivery ждут KUK-5.

## Корректность сверки AWG

v0.17: выбранный серверный peer должен явно сообщать AdvancedSecurity=on; off или отсутствие поля дают безопасный conflict. Пропущенные клиентские RandomTrailers/DisableCookies больше не скрывают включённый серверный режим. Readback принимает bounded uint32 hex FwMark из showconf; клиентский импорт по-прежнему отвергает FwMark. Полный список до18 safe mismatch names сохраняется через ledger и readiness, включая проверенный реальный comparator result с17 конфликтами. Команды, schemas6/4/1 и pending gate сохранены. Отчёт: `docs/iteration-17.md`; источник формата и ограничения: `docs/awg-showconf-contract.md`. Это local source-format/regression verification; actual pinned tool/core/client acceptance остаётся открытой в KUK-5.

## Подготовка readiness

v0.18: trusted storage подготовка AWG candidate и повторная проверка под SQLite writer fence. Повторно проверяются AEAD/client-only format/credential uniqueness, current binding/revision и exact-byte immutable observation/TTL. JSON не восстанавливает candidate; ledger не заменяет Result. Это локальная основа будущего transition: ready/client verification остаются false, fence заканчивается при возврате, новых CLI/API/UI routes нет. Keyless profile-readiness не получает vault key и сохраняет secret_verified:false. Runbook: `docs/profile-readiness-runbook.md`; решение: ADR-0016; отчёт: `docs/iteration-18.md`.

## Частичная сверка Xray users

v0.19: `profile-observe-xray-users` читает named users через fixed pinned Xray CLI и numeric loopback API; два bounded readbacks, immutable binding/exact bytes/target/TTL60s и повтор storage guards после чтения. UUID wire aliases резервируются при импорте консервативно, exact export bytes unchanged. API enumeration неполна; отсутствие не подтверждает revoke. Core identity/revision/REALITY transport/client/ready false, blocked exit1. Ledger/audit/state не пишутся. Runbook: `docs/profile-xray-users-runbook.md`; source pins: `docs/xray-users-contract.md`; отчёт: `docs/iteration-19.md`. Native positive/core/client acceptance не выполнена.

## Ограничение времени observer

v0.20: оба Linux observer ограничивают также ожидание inherited stdout/stderr: отдельная process group, SIGKILL при отмене, WaitDelay200ms и cleanup после раннего parent exit. Неполный/ошибочный readback очищается и не становится proof. Local helper-process regression tests не являются AWG/Xray native acceptance. Fixed descriptor/pin/args, pending gate, schemas6/4/1 и UI/API сохраняются. ADR-0018, iteration-20.

## Область AWG runtime

v0.21: immutable AWG runtime target связывает interface/endpoint/tool pin/current boot ID/netns device+inode с profile/exact bytes/revision/TTL. Observe сверяет fixed proc environment на locked OS thread до/между/после readbacks; storage/prepare/fenced recheck требуют independently expected target. Snapshot/JSON не превращаются в native scope. Ledger target не хранит; keyless runtime_target_verified:false и обязательный blocker. Local contracts/proc negative tests не закрывают native/core/client/transition acceptance. ADR-0019, iteration-21; схемы6/4/1 без миграции.

v0.22: partial Xray users Result теперь связывает independently expected boot ID/netns device+inode с API server/tag/tool pin/current profile/revision/exact bytes/TTL. Observe сверяет fixed proc environment на locked OS thread перед/между/после двух readbacks. Общий internal/runtimeenv используется AWG и Xray; AWG scope/guards сохранены. ExecutionScopeBound относится только к области исходного выполнения; Enumeration/CoreIdentity/Revision/Transport/Clients/Ready остаются false. Snapshot/JSON не приобретают native scope; storage read-only, blocked/exit1, profiles pending. Native/core/client/transition acceptance открыта; схемы6/4/1 без миграции. ADR-0020, iteration-22.

v0.23: Xray Observe требует exact-byte independently expected InventorySHA256 для fixed protected /etc/family-vpn/xray-inventory.json. Closed version1 JSON содержит expected boot/netns/kernel release и до16 API/tag/tool/core/config revision expectations. Linux descriptor walk проверяет root ownership/permissions/no symlink/hardlink/special files/64KiB bounds и metadata до/после чтения. CLI проверяет manifest до key/DB; observer повторяет inventory перед/между/после reads. Immutable Result/Check/store target связывает inventory pin; inventory_bound относится к исходному выполнению. Declared core/version/config/kernel metadata не observed core attestation: full Xray acceptance flags false, blocked/exit1, read-only/no ledger/state/audit writes. AWG contract и схемы6/4/1 сохранены; native/core/client/transition acceptance открыта. ADR-0021, xray-inventory-runbook, iteration-23.
