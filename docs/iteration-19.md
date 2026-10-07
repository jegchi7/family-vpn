# Итерация19 · v0.19.0 · 05.10.2026

## KUK-5 / M1-02 / DEV-08

Добавлены partial Xray users parser, fixed pinned Linux read-only adapter и trusted CLI profile-observe-xray-users. Scoped immutable Result привязан к exact stored bytes, current owner/device/profile/generation/revision и API server/tag/tool pin, TTL60s. Two readbacks нормализуются по содержимому, различный порядок JSON/users не даёт false drift. После API calls storage повторяет binding/key/AEAD/format/uniqueness/bytes/TTL guards; DB читается read-only, ledger/audit/state не пишутся. Всегда blocked/exit1, profile pending; partial не принимается AWG readiness типом.

Upstream source pin 7da5dae6502b787fc6d903863e9a6c5043d107a2 выявил UUID wire aliases bytes6/7 и неполную email-only enumeration. SameCredential резервирует такие aliases при импорте, snapshot/users parser отвергают duplicate wire identity; exact export bytes/UUID не переписываются. Отсутствие в ответе — unobserved, не отсутствие/revoke. Core identity/revision/transport/client/ready flags false. Source inspection и injected-reader tests не являются actual native execution. Details: xray-users-contract, ADR-0017, profile-xray-users-runbook.

## Проверки

`npm run check` PASS: Go vet/race всех packages, API generation без drift, Svelte0 errors/warnings и Vite build. `npm run build` PASS: frontend +6 Go binaries. `npm run test:persistence` и `npm run test:intents` PASS. Xray users fuzz10s/124421 executions PASS. Gofmt clean. UI/API/tests bytes unchanged (22 files), новый browser E2E не запускался.

Regression coverage: strict JSON/type/field/depth/size/user count/duplicate wire identity, exact/alias/unobserved/flow comparisons, normalized ordering, immutable redacted Result, TTL boundaries/exact bytes/current revision/target rebind, cancelled/unavailable/drifting injected reader, bounded native output, encrypted read-only storage/current revision/installed-state/download gate, alias race across two DB handles и rotation/exact bytes/continued alias exclusion, CLI bypass/external-target rejection. Keys/UUIDs генерируются в памяти/temp encrypted DB.

Two native Unix tests TestPeerUIDAndStrictSocketBody/TestSocketApplyLostResponseThenReconcile подтверждённо SKIP/AF_UNIX restriction; FVPN_REQUIRE_UNIX=1 acceptance отдельно. Native Xray binary/API/core/client не запускались; runtime contract использует injected reader. Original63 work/dependencies/acceptance автоматически сравнены с v0.18 без изменений.

## Статусы

KUK-5 In Progress, четыре native/Xray/client/transition пункта unchecked. KUK-6/7 ждут full readiness; KUK-19 In Progress; KUK-8 G1 Backlog. Snapshot1.14 сохраняет все original63 criteria и statuses45/15/3/0, GW8Backlog; auth extras Deferred. Схемы6/4/1 без миграции, Go deps unchanged, UI/API unchanged. Нет VPS/network config/deploy/assignee/messages действий. Native positive AWG/Xray/core/client и GitHub remote CI не заявлены. Runtime state/keys/deps/build/research sources не включаются в source archive.

Sync receipt v0.19: KUK-5/project baseline/M1 milestone обновлены в Linear и прочитаны обратно. KUK-5 In Progress, четыре full acceptance пункта unchecked; original acceptance/relations и IDs сохранены, snapshot1.14. Native/core/client acceptance не закрыта partial users observer.
