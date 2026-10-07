# Итерация16 · v0.16.0 · 05.10.2026

## KUK-5 / M1-02 / DEV-08

Продолжена работа по актуальной карточке Linear KUK-5. Реализован keyless trusted CLI `profile-readiness`: read-only report current target и blockers. Explicit canonical IDs, active ordinary owner, current profile/device/generation/revision; одна read transaction. Old target, foreign/disabled/admin owner не получают report. Ciphertext читается только как IS NOT NULL, ключ и plaintext не загружаются; stored_export не является secret verification.

Latest scoped ledger row проверяется по safe source/ID/field allowlist/canonical timestamps/TTL60s и current binding. Snapshot/fresh match/conflict/expired/future/stale binding различаются; newer conflict не скрывается older match. Timestamp sorting учитывает fractional seconds. Malformed metadata не попадает в error/DTO. Read model не является native attestation, fencing token или transition authorization.

CLI `status:blocked` и exit1 даже при fresh stored runtime match: secret_verification_required, client_acceptance_missing и readiness_transition_unavailable остаются обязательными. Нет flags apply/key/ready/client-verified/snapshot. Error JSON sanitized; missing/old DB не создаётся и не мигрирует. Нет HTTP/control/socket exposure, network/tool calls, mutations, ready/installed_revision или выдачи профиля. Schema6/4/1 без миграции. Runbook: profile-readiness-runbook.md; ADR-0014.

## Проверки

Go store/CLI race tests: matrix missing/native/snapshot/conflict/future/expiry-boundary/stale binding; latest fractional conflict wins; no fallback после expiry; actual rename invalidation; foreign target/ledger owner, old generation/revision, disabled/admin owner, missing import/REALITY observer/revoked state; corrupt fields/timestamps/TTL; no audit/state/revision mutation и SQL read-only handle. CLI actual blocked report/nonzero, flag bypass/redaction и отсутствие создания missing state проверены.

`npm run check` PASS: Go vet/race всех packages, API generation drift, Svelte0 errors/warnings и Vite build. `npm run build` PASS: frontend и шесть Go binaries. `npm run test:persistence` PASS, включая built CLI profile-readiness и запрет apply; `npm run test:intents` PASS: admission/replay/conflicts/cancel/pages, persisted retry/process restart/SIGTERM, no runtime apply. Formatting check новых Go files чистый. Original63 IDs/work/dependencies/acceptance сравнились с предыдущей поставкой без изменений; statuses45/15/3/0.

`TestPeerUIDAndStrictSocketBody` и `TestSocketApplyLostResponseThenReconcile` SKIP: AF_UNIX запрещён средой. Это не PASS native acceptance. UI/API source не менялись; browser E2E в этой поставке не запускался. Actual core/kernel/tool/runtime, VPN-клиент, routing/DNS/handshake не проверялись. Synthetic ledger rows в тестах — только read-model fixtures; private credentials генерируются в памяти и runtime temp directories.

## Linear и реестр

KUK-5 остаётся In Progress; v0.16 закрывает только локальный diagnostic slice. Audited readiness transition и native/client пункты не закрыты. KUK-6/7 delivery/QR и KUK-8 G1 остаются Backlog; KUK-18 Done только local importer, KUK-19 In Progress. Linear — current milestone/task tracking; canonical snapshot1.11 сохраняет исходные63 ID/criteria:45 Backlog/15 In progress/3 Verification/0 полностью Done; GW8Backlog. Git/deploy/VPS не выполнялись. Runtime/deps/build/test artifacts и секреты не включаются в source archive.
