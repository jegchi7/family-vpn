# Итерация 08 · v0.8.0

Дата: 4 октября 2026. Результат — trusted importer ограниченного VLESS/REALITY URI с read-only dry-run, explicit apply и безопасным pending UI. DEV-08 продвинут, actual peer reconciliation/AWG compatibility остаются открытыми. Новых auth mechanisms нет; приоритет владельца сохранён.

## Выполнено

- Исследование первичных Xray/Project X/Amnezia документов, собственная матрица `client-format-matrix.md`. Поддерживается один `vless-reality-uri` subset TCP/Vision/chrome; AWG 3.1, vpn://, JSON, wrappers и расширения пока закрыты. Синтаксическая проверка не объявлена тестом реального приложения.
- `internal/clientconfig`: строгая allowlist значений/полей, проверка UUID/authority/port, SNI/pbk/sid/escapes, duplicate fields, размеров и единственного URI. Unknown/server/management fields и password userinfo отвергаются. Errors/metadata formatting не выводят raw URI или identity. Optional final LF/CRLF сохраняется вместе с bytes.
- Bounded input из stdin либо private regular file: current UID, private parent/file, отсутствие symlink/aliased parent; nonregular/oversize/empty/public input закрыт. Не требуется передавать config в argv/env.
- `profile-targets --login`: owner/device/profile/protocol/current generation/revision/state/format/stored, без endpoint/credentials/config. Выбор активного ordinary user, optional device filter.
- `profile-import`: default read-only dry-run; `--apply` повторяет все проверки в writer transaction и сохраняет encrypted pending bytes/audit/device revision. Sanitized JSON codes и nonzero failure exit; explicit ready:false/peers_verified:false в каждом отчёте. Нет автоматической миграции/new DB/ключа.
- Store boundary `ImportClientProfile` повторно валидирует bytes, owner/device/current generation/pending/revision и active key. Exact retry возвращает already-stored; иное содержимое конфликтует. Preview не резервирует revision и не разрешает последующий stale apply.
- Один UUID не назначается двум неотозванным профилям, включая disabled owners и другие поколения. Check decrypts known imports in memory, не хранит UUID/hash в БД и не печатает данные другого profile. Конкурирующие DB handles сериализуются; key rotation сохраняет detection.
- Shared staging checks выделены из прежнего StageProfileSecret без изменения его trusted internal scope. Audit failure откатывает ciphertext/revision. Нет peer/IP/installed proof/state ready/network adapter.
- Pending UI показывает **«Сохранён, ждёт сверки»** и пояснение о неподтверждённой установке; скрывает cancel для выбранного format. Server cancel/download guards сохраняются; нет links/URI/UUID/pbk. Обновлены OpenAPI enum/generated TS, versions, README/AGENTS, ADR-0009 и runbooks.

## Проверки

| Проверка | Результат |
|---|---|
| `npm run check` | PASS: Go vet/race tests, API generation drift, Svelte/TS 0 errors / 0 warnings, Vite build |
| `npm run build` | PASS: frontend и 6 Go executables |
| `npm run test:persistence` | PASS: persistence/revision/ownership/readiness/listener regressions |
| Demo browser | 4/4 PASS, desktop/mobile |
| User/auth/device/import browser | 8/8 PASS: прежние flows и compiled CLI targets → dry-run/apply/retry → pending UI |
| Admin browser | 2/2 PASS, password/TOTP/session regression |
| Final parser correction | Check/build PASS; 2 compiled CLI import browser scenarios повторно PASS после проверки bracketed hosts и DNS-only SNI |
| Format/source validation | PASS: duplicate/missing/unknown query fields, passwords/server keys/wrappers/JSON/SSH, invalid encoding/control chars, sizes, unsupported modes; private input permissions/symlink/size |
| Byte preservation | PASS: validation не меняет bytes; decrypt after import точно совпадает с original URI, включая percent encoding/query order/CRLF |
| Dry-run | PASS на read-only DB: не пишет secret/audit/revision; существующий payload распознаётся; stale apply после rename конфликтует |
| Binding/replay | PASS: foreign target, wrong protocol/current generation/revision, exact repeat, payload conflict, pending download/cancel rejection |
| Credential conflict | PASS: другой owner/profile с тем же UUID отклонён в dry-run/apply; rotation не теряет conflict; два DB handles дают один success и один conflict |
| Atomic audit | PASS: error откатывает import и device revision; существующие vault/rotation rollback tests сохранены |
| CLI report privacy | PASS: success/failure/targets не содержат URI/UUID/pbk; unknown flags не echo input; exit соответствует report status |
| Parser fuzz | PASS: final 3s run — 135 585 executions без panic, 2 workers. Это ограниченный fuzz smoke, не exhaustive review |
| UI metadata/privacy | PASS: format/state без UUID/pbk; нет download/cancel buttons; pending API download/cancel 409; mobile overflow отсутствует |

Полный браузерный набор — **14/14 PASS**; затем 2 import scenarios повторно после последней guard correction. Final desktop/mobile screenshots просмотрены: `screenshots/iteration08/import-pending-{desktop,mobile}.png`; обычные device screenshots также в этом каталоге. Секретные поля не представлены на снимках.

Среда: Linux x86_64, Go 1.27.1, Node 24.19.0, npm 11.9.0, Playwright 1.63.0, Chromium 153.0.8010.0. External launch configs использованы для доступного local Chromium; source содержит обычные Playwright configs. Self-signed TLS допускается только browser test settings. Frontend JS gzip около 25.64 kB; это размер bundle, не измерение VPS RSS. Remote CI не запускался.

## Бэклог и ограничения

Canonical `vpn-platform-backlog-v1.0.md` обновлён до содержимого версии 1.3, имя/ID/критерии сохранены. **PRE-04 и DEV-08: Backlog → In progress**. DEV-07 остаётся Verification; DEV-09 отражает imported-pending UI. Итого **47 Backlog, 13 In progress, 3 Verification, 0 Done по полным исходным критериям**; плюс 8 GW Backlog без runtime pairing/apply. Historical reports 01…07 и baseline specification не переписаны.

Новых DB migrations нет: portal v5/control v2/admin v1. Существующие vault encryption/AAD/key rotation продолжили работать с импортированными URI. Хранилище поддерживает opaque internal staging, CLI использует только проверенный ImportClientProfile; arbitrary opaque upload не добавлен.

UUID exclusivity — локальная политика MVP, а не универсальное требование VLESS. Linear credential scan соответствует семейному масштабу; большой объём/timeout отдельно не benchmarked. Original plaintext source остаётся у trusted operator. URI parser неизбежно создаёт временные string copies; best-effort byte clear не является гарантией отсутствия секретов в process memory/core/swap.

Actual RU endpoint/peer/parameters, network handshake, client import и AWG 3.1 preservation не проверены. Импорт не устанавливает доступ и не включает download. Нет ложного installed revision, network call или удаления unknown peers. Full-access wrappers не поддерживаются; схематическая валидация не доказывает происхождение каждого secret-looking field из конкретного сервера.

Реальные VPS/firewall/routes/SSH, Git/publish/deploy не изменялись. Production isolation/backup recovery, Windows ACL/macOS и доступность из РФ не доказаны. G0/G1 и следующие gates открыты. Следующий шаг — actual-peer evidence/reconciliation, затем owner download и реальный client round-trip; см. `next-iteration.md`.

Архив содержит source/docs/screenshots; runtime state/keys, input exports, credentials, dependencies и binaries исключены.
