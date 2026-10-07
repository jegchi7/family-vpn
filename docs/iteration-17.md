# Итерация17 · v0.17.0 · 05.10.2026

## KUK-5 / M1-02 / DEV-08

Исправлены ложные совпадения AWG readback. Selected AdvancedSecurity off/missing возвращает safe advanced_security conflict; flag другого peer не закрывает target. RandomTrailers/DisableCookies сравниваются с omitted=off на обеих сторонах. Readback принимает bounded hex uint32 FwMark upstream showconf; client importer и routing не меняются.

Общий vocabulary18 safe mismatch names для comparator/readiness вместо reader limit16. Проверен actual comparator result с17 конфликтами через encrypted import → scoped observation/audit → read-only readiness: весь список сохраняется, DTO без plaintext/key/endpoint. Foreign/drift/stale bindings и pending gate сохраняются. Схемы6/4/1 без миграции, UI/API/CLI commands без изменений.

Upstream showconf.c и go uapi.go исследованы с concrete commit/hash; source contract записан в awg-showconf-contract.md и ADR-0015. Inspected go UAPI не сообщает selected peer AdvancedSecurity: positive observer subset остаётся blocked без core-specific evidence. Это не native tool/core/client acceptance.

## Проверки

Targeted clientconfig/profileobserve/store tests PASS. `npm run check` PASS: Go vet/race всех packages, API generation без drift, Svelte0 errors/warnings, Vite build. `npm run build` PASS: frontend и6 Go binaries. `npm run test:persistence` PASS; `npm run test:intents` PASS. AWG snapshot fuzz10s/50 368 executions PASS; gofmt чистый. UI/API bytes без изменений (28 files); новый browser E2E не запускался. Регрессии selected on/off/missing/other peer,9 boolean combinations для каждого режима, bounded FwMark positive/negative и client management rejection, full17 mismatch ledger round-trip и безопасный18-name vocabulary. Private test keys генерируются в памяти/temp encrypted DB.

## Linear и следующие шаги

KUK-5 In Progress. Срез comparator исправлен; native/runtime/client/transition acceptance остаётся открытой. KUK-6/7 download/QR ждут readiness, KUK-19 полный путь In Progress, KUK-8 G1 Backlog. Original63 work/dependencies/acceptance сохраняются, snapshot1.12, statuses45/15/3/0; GW8Backlog. Auth extras Deferred. Нет assignees/messages/deployment/VPS действий. Runtime/deps/build/test state/secrets не включаются в source archive.

Два Unix tests `TestPeerUIDAndStrictSocketBody` и `TestSocketApplyLostResponseThenReconcile` SKIP: sandbox запрещает AF_UNIX. Native acceptance отдельно с FVPN_REQUIRE_UNIX=1 на разрешённом стенде. Actual binary/core/kernel/client, handshake/DNS/routing не проверялись; source inspection и synthetic tests не закрывают их критерии. Original63 ID/work/dependencies/acceptance сравнились с authoritative v0.16 без изменений.

Sync receipt: существующая KUK-5, project baseline и M1 milestone обновлены напрямую в Linear и прочитаны обратно. Status In Progress, четыре native/runtime/client/transition пункта остаются unchecked; block relations KUK-6/7/8 сохранены. Ни одна полная legacy acceptance не закрыта local comparison code.
