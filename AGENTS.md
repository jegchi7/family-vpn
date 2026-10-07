# Работа над проектом

Читать README.md, docs/iteration-24.md, docs/next-iteration.md. Нормативные требования и backlog находятся в docs/vpn-platform-*.md; iteration report уточняет только фактический прогресс, не отменяет требования.

- Приоритет владельца 05.10.2026: завершать M1/G1 итеративно до возврата к M2. AWG31Conf — single client Interface/Peer, allowlist без hooks/management, exact bytes, uniqueness по derived public key с учётом clamping. Native compatibility не обещать; snapshot/fake/CLI apply не делает ready. M1 acceptance: docs/milestone-m1.md.

- profile-observe-awg только читает текущий netns через pinned root-owned /usr/bin/awg; нельзя принимать произвольный executable/snapshot под видом native source. Результат immutable, TTL60s, привязан к owner/device/profile/generation/revision и точным bytes; apply хранит только safe metadata/audit. Никогда не устанавливает ready/installed_revision. Native positive acceptance и client round-trip ещё не пройдены. Current task tracking в Linear, KUK-5; original63 criteria сохраняются в canonical snapshot.

- Не считать demo authentication реализацией AUTH. Никогда не разрешать ему публичный bind.
- Не подключаться к VPS, не менять firewall/routes/SSH и не публиковать приложение из задачи локальной разработки.
- Fail-closed и host management isolation обязательны. Не добавлять DIRECT как fallback.
- Публичный процесс не получает agent socket, control DB или docker.sock. Не переносить admin routes в публичный router.
- Секреты запрещены в fixture, logs, tests, docs, URLs и git. Не принимать full-access Amnezia export в клиентском кабинете.
- Сохранять API generation. Новую функцию проверять на существенных границах; не писать бессмысленные тесты представления.
- Обновлять iteration report честно: runtime demo не закрывает production acceptance tasks.
- Не выдавать гипотетические netns/systemd шаблоны за проверенный deploy.
- После изменения: npm run check; после UI flow — e2e. Если инструмент недоступен, зафиксировать ограничение без заявления об успешном тесте.

- Local-auth использует отдельную portal DB и HTTPS loopback; demo identity не допускается в этот режим. Password-only admin всегда запрещён: только подтверждённый TOTP создаёт сессию.
- После auth flow запускать также npm run test:e2e:auth и npm run test:e2e:admin; не публиковать generated credentials, БД и TLS keys.

- User recovery отключает password/sessions сразу при trusted CLI issuance. Не разрешать anonymous issuance или обход admin/MFA/passkey; recovery не меняет VPN profiles.

- Admin credentials хранятся в отдельной DB с собственным application_id; public процесс не открывает её и master key. Admin HTTP читает portal DB read-only. Ключ не помещать в DB root/backup, runtime не генерирует ключи.
- Snapshot v0.5 поддерживает admin MFA только на Linux local stand; не ослаблять проверки ключа ради Windows ACL. Fresh auth отложен решением владельца для текущего MVP; опасных admin HTTP mutations пока нет.

- Приоритет владельца 30.09.2026: DEV-06/07/08/09 перед WebAuthn/recovery codes/fresh auth. Существующий password/TOTP сохранять. Основной backlog обновлять в каждой поставке; не ограничиваться iteration reports.
- Device request только резервирует слот и pending profiles. Cancel не является network revoke: не разрешать его после выдачи/импорта любого поколения или подписки.

- Profile vault — отдельный purpose-tagged key вне user state root; admin TOTP key не переиспользовать. Runtime HTTP пока не загружает profile key. Trusted StageProfileSecret — внутренний storage API. CLI import обязан использовать ImportClientProfile и clientconfig validator; staging не является доказательством установки peer.
- Ротация profile key атомарна для всех состояний/поколений; старый файл сохраняется, stale writer отклоняется. Не добавлять CLI произвольного plaintext import/dump в обход DEV-08/PRE-04.

- profile-import по умолчанию read-only dry-run. Apply повторяет проверки в writer transaction. Ошибки/JSON report не содержат URI/UUID/pbk/input path, конфликт credential сериализуется между DB handles. Не делать произвольные full-access wrappers или unknown URI fields допустимыми.
- Сохранять точные bytes экспорта; перед ready/download требуется отдельная actual-peer сверка и проверенный клиент. VLESS URI subset не закрывает AWG 3.1 compatibility.

- profile-preflight читает DB read-only; snapshot и privateKey только в trusted CLI memory, не DTO/DB/logs. SHA pin — конфигурационная ревизия, не freshness/attestation. Не делать ready по одному совпадению snapshot.
- Цель владельца 04.10.2026: итеративно пройти полный backlog с промежуточными архивами. Основной реестр и локальные подзадачи обновлять в каждой поставке; реальные NET/QA/ROL criteria не закрывать локальным fake.

- AdminData interface только на authenticated management listener; user/demo не получают admin views. Read-only pages ≤100, allowlisted state/cursors, no raw audit actor/object/action payloads, tokens/hashes/key IDs. Timestamp ordering учитывает fractional seconds.

- Catalog versioned/embedded/non-secret. Portal verification не client compatibility; draft clients без install/deep links. Offline HTML template escaping, no external resources/scripts or personalization. Never derive profile ready from catalog claims. Не запускать Vite build/clean одновременно с browser tests, читающими тот же dist.

- Intent fake stand не production boundary: one-UID/shared control observation только synthetic. Unix EPERM tests могут skip локально; FVPN_REQUIRE_UNIX=1 обязателен для native acceptance. Public/admin не подключать к control/socket. Lease expiry не success, completion только observed evidence/current attempt; tombstones не отменять и не считать подтверждённым network revoke.

- Retry durable2..60s, unknown stays reconciling/blocks node; no terminal state from attempt count. Cancel только queued Ensure attempts0/no evidence, never Revoke/tombstones. Worker shutdown не отменяет intent; bounded retry journal allowed, no new apply. Read-only operation metadata только trusted CLI; не добавлять control DB к HTTP ради dashboard.

- profile-readiness — keyless read-only CLI diagnostics, не permission/transition. Latest conflict/expired/stale/future metadata не скрывать старым совпадением. secret_verified/clients_verified/ready false; нельзя добавлять manual ready/client checkbox или key/snapshot/apply flags. В report не переносить raw fields/values, tool/network calls и control DB.

- AWG readback v0.17: выбранный peer требует explicit AdvancedSecurity=on; off/missing дают advanced_security conflict. Boolean omission — off на обеих сторонах в текущем subset. Hex FwMark разрешён только в readback, client import не расширять. Safe mismatch vocabulary общий для comparator и readiness; полного native acceptance это не подтверждает.

- v0.18 PrepareAWGReadiness/RecheckAWGReadiness — trusted-only подготовка и writer-fenced rollback, никогда не permission/lease/ready. Candidate JSON не восстанавливается; keyless CLI unchanged. Будущий audited transition обязан проверять actual client proof и все guards в одной writer tx, не recheck → отдельный ready update.

- v0.19 profile-observe-xray-users: partial named-users API only, fixed pinned tool/numeric loopback, no apply/ready/input/tool. API absence не подтверждает revoke; responding core/revision/transport/client/ready false, blocked exit1. UUID aliases bytes6/7 резервируются консервативно, export bytes unchanged. Partial Xray Result не AWG readiness evidence; native/core manifest/client acceptance остаются открыты.

- v0.20 observerexec bounds inherited pipes/process-group cancellation; errors clear readback. Never treat helper tests as native VPN acceptance or process-group cleanup as hostile-executable containment.

- v0.21 AWG Observe/Record/Prepare/Recheck require independently expected target; boot/netns read from fixed proc paths on locked OS thread. No default/autopick/setns or manually relabelled snapshot. Native/core/client/transition acceptance still open; historical ledger never verifies target.

- v0.22 Xray Observe/Check/read-only store recheck require independent boot/netns scope. Shared runtimeenv fixed proc reader runs on locked OS thread. ExecutionScopeBound never core/revision/client/ready attestation; snapshot zero target only, partial flags false, blocked/exit1.

- v0.23 Xray native observer requires fixed protected xray-inventory.json and independent InventorySHA256. InventoryBound is expected manifest provenance/binding only: declarations cannot certify responding core/config/kernel/client. No arbitrary inventory path/autopick/manual ready; AWG unchanged.
