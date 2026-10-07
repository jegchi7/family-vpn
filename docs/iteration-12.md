# Итерация 12 · v0.12.0 · 04.10.2026

## Результат

Начаты DEV-14/15. Strict synthetic intent schema1 (4096 bytes), exact/unique JSON keys, bounded IDs/counters, только ReadState/EnsureDeviceProfiles/RevokeDeviceProfiles. Нет arbitrary command/path/service/config/endpoints. В fake subset один profile target/generation; это не полный AWG+REALITY device payload.

Control schema3: durable operations+canonical hash/idempotency, expected observed node revision, serialized claims между DB handles, revoke priority и append-only per-node generation tombstones. Expired lease → reconciling перед новыми intent, attempts fencing, persistent before_apply/observed checkpoints. Fake runtime delta и evidence атомарны в SQLite. После потери ответа runner сначала сверяет observed state; completion проверяет evidence/request hash/node revision/актуальный attempt самостоятельно. Нет success по одному ответу или timeout, повтор не дублирует mutation. Приоритетный monotonic revoke rebases к current revision, stale Ensure не применяется. Tombstone при admission не является confirmed runtime revoke.

`hop-controller --fake-stand` реализует init/enqueue/status/step; `node-agent --fake-stand` — fixed-node Linux Unix transport с exact SO_PEERCRED UID, private socket, bounded concurrency/timeouts и strict body. Default fail-fast сохранён; отдельный synthetic marker требует пустую DB и не принимает demo/populated unmarked state. Runtime открывает актуальную существующую schema без migration. Ни один HTTP process не получил control/socket или mutations. Нет ядровых вызовов, profile ready/download, VPS/Git/deploy; foreign-probe placeholder и выбор hop ещё не реализованы.

ADR-0010, local agent JSON schema и intent-stand-runbook описывают обязательную native приёмку и границу fake/production. Fake runtime и queue намеренно разделены таблицами одной DB/UID; это **не** production privileged-agent storage/trust model.

## Проверки

- `npm run check` PASS: Go vet/race, API generation drift, Svelte0 errors/0 warnings, Vite. Повтор после финального guard — результат ниже соответствует окончательному source.
- `npm run build` PASS: frontend+6 executables. `npm run test:persistence` PASS (control migration3), `npm run test:intents` PASS (CLI opt-in/init/admission/replay/conflicts/status, без runtime).
- Strict decoder rejection matrix PASS. Queue concurrency/idempotency между handles, node serialization/independent nodes, stale revisions, generation revocation priority/suppression, expired-before-apply, lost-response/reopen/reconcile, old-attempt fencing, non-adoption of demo/populated control PASS.
- In-process reconciler fault injection PASS: runtime applied/response lost → reopen → observed completion; exactly one applied record/revision increment. Forged success без runtime evidence отклонён.
- **2 Unix tests SKIP**: создание AF_UNIX возвращает EPERM в текущем sandbox. Они написаны, но не выполнены; `FVPN_REQUIRE_UNIX=1` запрещает skip для Linux acceptance. SO_PEERCRED/native round-trip не объявлены проверенными.
- Browser regression попытался запустить user10/admin2/demo4 сценария, но все16 остановились при запуске Chromium, до application assertions. Отдельный `chromium --version` также exit139/SIGSEGV. **E2E текущей версии не выполнен**, PASS не заявляется. web/src byte-identical v0.11; последний успешный browser результат находится в iteration-11, не перенесён как текущая проверка.

Linux x86_64, Go1.27.1, Node24.19, npm11.9. Final UI assets unchanged, source baseline specification/history01–11 сохранены. Runtime DB/TLS/credentials/binaries/dependencies/test output не входят в архив.

## Бэклог и следующий срез

Canonical backlog1.7 обновлён: DEV-14/15 Backlog→In progress; всего45 Backlog/15 In progress/3 Verification/0 Done по полным63 criteria; GW8Backlog. Родительские DEV-14/15 не закрыты: публичный limited bridge, production UID boundary, actual runtime evidence, полноценные mutations/worker и network crash tests ещё впереди. Portal/control/admin5/3/1.

Следующий независимый срез DEV-15 — durable worker scheduling/retry/cancel и safe management operation views, затем separate agent runtime/observer и native Linux stand acceptance. Real adapters DEV-16/17 зависят от PRE/NET inventory/core/client inputs. AWG3.1 native parsing, actual peer+client round-trip/download, gateway pairing и liveNET/QA/ROL остаются открыты; fake результат не заменяет эти критерии.
