# Итерация15 · v0.15.0 · 05.10.2026

## Срез M1-02 / DEV-08

Добавлены bounded AWG showconf parser и сверка peer/server keys, endpoint/port, shared wire parameters, PSK и client host addresses/overlap. Snapshot source отдельно от native source. Linux observer выполняет только два read-only вызова pinned root-owned `/usr/bin/awg` через file descriptor в текущем netns; drift, неизвестные поля и unavailable source закрываются безопасной ошибкой. Runbook: profile-observation-runbook.md; ADR-0013.

Immutable result привязан к owner/device/profile/generation/device revision и exact client bytes, TTL60s. Trusted CLI `profile-observe-awg` default read-only; apply повторно проверяет state/binding/bytes и атомарно сохраняет только safe metadata/audit. Replay не дублирует запись. Server snapshot/private key/raw values не попадают в ledger или вывод. Portal migration5→6 сохраняет encrypted profiles; control/admin4/1 без изменений.

Readback не устанавливает ready/installed_revision, не выдаёт профиль, не меняет peers/network/address allocation. Client round-trip и native positive acceptance не выполнены. Xray остаётся config preflight. M1-02 частично реализован; G1 открыт.

## Проверки

- `npm run check` PASS: Go vet/race all packages, API generation drift, Svelte0 errors/warnings, Vite build.
- `npm run build` PASS: frontend и шесть Go binaries.
- `npm run test:persistence` PASS: CLI state/repeat init/ownership/revision/HTTP boundary, portal6/control4.
- `npm run test:intents` PASS: admission/replay/conflicts/cancel/pages, unavailable-agent retry/process restart/SIGTERM; runtime apply не выполнялся.
- Observer/store/CLI race tests PASS: dual stack binding, immutable/redacted summary, TTL/future/bytes/owner/revision, malformed/unknown/duplicate readback, missing/duplicate peer и адресный overlap, native read contract/drift/backend sanitization/interface bounds/stdout bounds, audit rollback/replay/pending gate, migration5→6 byte-exact ciphertext.
- Fuzz `FuzzAWGSnapshotNeverMutatesOrEchoes`5s/2 workers PASS:43792 executions, без сбоя/изменения input/unsafe error.

Native read contract test использует injected reader; действующие AWG tool/kernel/interface и VPN-клиент не проверялись. UI source не менялся; browser E2E не запускался в этой поставке. Известные прежние ограничения среды Chromium startup SIGSEGV и AF_UNIX EPERM остаются непринятыми native/browser критериями; исторические screenshots не являются новым доказательством.

## Реестр и Linear

Canonical backlog1.10 сохраняет исходные63 ID и критерии:45 Backlog/15 In progress/3 Verification/0 Done; GW8Backlog. M1-01 локально завершён в v0.14, M1-02 observer/ledger локально проверен в v0.15; фактическая readiness/client acceptance ещё открыта.

Linear plugin установлен, но в текущей сессии нет доступных действий чтения/записи Linear. Внешние карточки не созданы и не изменены. `linear-sync-plan.md` — конкретный черновик для синхронизации после доступа к workspace/team/workflow; external IDs и assignees не придуманы. Git/deploy/VPS не выполнялись. Source archive не содержит runtime DB, credentials, dependencies, executables или test artifacts.
