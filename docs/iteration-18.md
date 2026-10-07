# Итерация18 · v0.18.0 · 05.10.2026

## KUK-5 / M1-02 / DEV-08

Добавлена подготовка AWG readiness в trusted storage boundary: opaque in-memory candidate после повторной AEAD/AAD/format/uniqueness проверки точных stored bytes и scoped observation. Writer-fenced recheck повторяет current owner/device/profile/generation/revision/key/bytes/TTL guards после получения блокировки и откатывается. Historical ledger и JSON не заменяют immutable Result. Pending профиль с installed_revision отвергается также существующими observation load/record методами.

Candidate не содержит plaintext; JSON не восстанавливает его, обычное форматирование не раскрывает binding/digest, Summary копирует blockers. SecretVerified относится к новой trusted transaction; keyless CLI остаётся без ключа и secret_verified:false. Snapshot/conflict получают blockers. ClientsVerified/Ready всегда false: actual client attestor и audited transition отсутствуют. Fence заканчивается при возврате; результат не разрешает последующую отдельную ready запись.

Recheck не выполняет новое runtime измерение. Для приёмки нужны actual scoped readback, согласованный core-specific security contract и pinned client round-trip. Детали: ADR-0016 и profile-readiness-runbook. Схемы6/4/1 без миграции; новых CLI/API/UI flows нет.

## Проверки

`npm run check` PASS: Go vet/race всех packages, API generation без drift, Svelte0 errors/warnings и Vite build. `npm run build` PASS: frontend +6 Go binaries. `npm run test:persistence` и `npm run test:intents` PASS. Новые readiness regressions входят в full race suite; targeted initial tests PASS. Gofmt чистый. Private test keys генерируются в памяти/temp encrypted DB.

Два native Unix tests `TestPeerUIDAndStrictSocketBody` и `TestSocketApplyLostResponseThenReconcile` подтверждённо SKIP/AF_UNIX sandbox restriction. На разрешённом стенде обязательна отдельная проверка FVPN_REQUIRE_UNIX=1. UI/API source bytes без изменений (16 файлов web/src+api, также все прежние web/tests сохранены); новые browser E2E не запускались. Native/core/client positive acceptance не выполнялась. Original63 task bodies/work/dependencies/acceptance автоматически сравнены с v0.17 без изменений; statuses45/15/3/0 сохранены.

## Статусы и границы

KUK-5 In Progress, четыре native/Xray/client/transition acceptance пункта открыты. KUK-6/7 ждут readiness; KUK-19 In Progress; KUK-8 G1 Backlog. Canonical snapshot1.13: original63 work/dependencies/acceptance сохранены, 45 Backlog /15 In progress /3 Verification /0 Done; GW8Backlog. Auth extras Deferred.

Нет VPS/network/deployment действий, изменения assignees или сообщений людям. Native AWG/Xray/реальные клиенты не запускались. Runtime/dependencies/build/test state/secrets исключаются из source archive. GitHub создание осталось отдельной незавершённой задачей; этот архив не заявляет GitHub CI/push.

Sync receipt v0.18: существующая KUK-5, project baseline и M1 milestone обновлены в Linear и прочитаны обратно. KUK-5 In Progress; четыре native/Xray/client/transition пункта unchecked и block relations KUK-6/7/8 сохранены. Snapshot1.13, оригинальные criteria/assignees не менялись.
