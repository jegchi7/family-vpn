# Итерация 13 · v0.13.0 · 04.10.2026

## Реализованный срез DEV-15

Foreground fixed-node worker с bounded polling, graceful SIGTERM, safe metadata events. Durable exponential retry2/4/8/16/32/60s сохраняется в control DB и переживает перезапуск; unknown outcome остаётся reconciling, а не получает terminal failure/success по числу попыток. После due time сначала observed read старой операции. Новые мутации узла не обходят unresolved intent. Lease10s, operation context8s, retry journal при отмене контекста ≤1s; current attempts fencing сохраняется.

Trusted CLI cancel только queued Ensure до claim/apply; повтор безопасен, actor/node ownership скрывает чужие операции. Revoke cancellation запрещена, tombstones не удаляются. Replay cancelled request не восстанавливает заявку. CLI list bounded1..100/sequence keyset/state filter; status/list/worker metadata содержит safe state/attempts/retry reason/deadline без actor/key/hash/envelope. HTTP control/socket доступ не добавлялся, UI source не менялся.

Control migration3→4 сохраняет pending intents и добавляет retry metadata defaults; runtime не мигрирует автоматически. Portal/control/admin5/4/1. ADR-0011 и updated intent runbook объясняют неопределённые состояния, cancellation и required native acceptance. Scheduler fake metadata, не реальный VPN/hop controller.

## Проверки

- Go race targeted store/reconciler/CLI PASS: durable retry across handles/reopen, exact delays/cap, old released lease rejection, cancel/claim race8 runs, actor/node scope, revoke protection, live keyset bounds/no unsafe DTO fields, migration3→4 preservation и runtime refusal of old schema.
- In-process lost-response recovery PASS: одна мутация, затем ReadState/observed completion без повторного apply. Два foreground worker применяют одну операцию один раз и останавливаются после cancellation. Unavailable agent не делает error terminal, raw backend error не попадает в report. Cancelled call сохраняет uncertain retry.
- `npm run test:intents` PASS: real CLI admission/replay/conflicts/cancel/list + unavailable-agent worker → SIGTERM → process restart → due retry/attempt2/deadline4s → SIGTERM; no runtime applied. Unix connection unavailable здесь намеренно, успех transport не заявляется.
- Final `npm run check` PASS (Go vet/race, API drift, Svelte0 errors/warnings, Vite), `npm run build` PASS (frontend+6 binaries), `npm run test:persistence` PASS; финальный `npm run test:intents` также PASS. Native Unix tests остаются2 SKIP при AF_UNIX EPERM; required acceptance `FVPN_REQUIRE_UNIX=1` запрещает skip.
- `chromium --version` по-прежнему exit139/SIGSEGV до приложения. UI flow не менялся, E2E этой версии не выполнен. Последний browser PASS — v0.11; не переносится как текущий результат.

Baseline spec/history01–12 сохранены. Runtime state, executables/deps/credentials/TLS/test artifacts не входят в архив. Git/VPS/deploy не выполнялись.

## Основной бэклог

Реестр1.8 обновлён: DEV-15 содержит worker/retry/cancel/list, DEV-02 control4. Полные статусы остаются45 Backlog/15 In progress/3 Verification/0 Done из63; GW8Backlog. Полный DEV-15 не принят: HTTP integration, независимый actual observer, real adapter crash/rollback, production service UID/transport и live network ещё впереди.

Следующий срез: отделить agent runtime/evidence от controller DB и реализовать ограниченный observer для fake stand; затем native transport/UID acceptance на разрешённом стенде. Публичные intents, real AWG/Xray, формат AWG3.1 и owner download требуют своих gates. Snapshot/fake successful state никогда не делает профиль ready.
