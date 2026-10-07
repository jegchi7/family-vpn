# ADR-0010 · Durable intents и synthetic agent stand

04.10.2026 · принято для локальной разработки, production integration не принята.

DEV-14/15 начинаются с узкого fake-стенда без VPN credentials, routes, firewall, systemd и вызовов ядер. Public/admin HTTP не получают control DB, socket или новый mutation route. Trusted `hop-controller --fake-stand` сохраняет намерения, отдельный `node-agent --fake-stand` принимает только фиксированный JSON. Оба отказываются работать без explicit opt-in. `foreign-probe` остаётся placeholder; контроллер ещё не выбирает hop.

## Контракт и доверие

`api/agent-schema/local-stand-v1.schema.json` — отдельный synthetic subset, не финальный privileged payload. ReadState/EnsureDeviceProfiles/RevokeDeviceProfiles, одна synthetic profile generation на target, schema1, 4096-byte limit, только ASCII IDs и bounded integer counters. Полный device с AWG+REALITY пока не моделируется. Unknown/case-alias/duplicate fields, nulls, arbitrary command/path/service/config/endpoint и прочие типы отклоняются. Agent принимает лишь точный envelope ранее сохранённой операции на своём фиксированном node. Actor и node задаёт доверенный consumer; public user не может выбрать их в payload.

Linux transport: owner-private symlink-free directory0700, socket0600, SO_PEERCRED точное совпадение explicit controller UID, 8 соединений, 3s I/O deadline и 2s handler context. Existing paths не перезаписываются. Stand предполагает доверенные ancestors, один service UID для controller/agent и private storage. Это не production DAC/systemd policy: shared control DB намеренно упрощает fake evidence и **не разрешается** как модель реального privileged agent. В production нужны отдельное runtime state, защищённый observer, разные public/management/agent UID, ограниченный public intent bridge, deployment ownership и независимые acceptance tests.

## Очередь и состояние

Control schema3 добавляет queue/fake runtime metadata; portal/admin остаются5/1. Stand bootstrap требует пустую DB, устанавливает `dataset=fake-intents-v1` и никогда не принимает demo или populated unmarked DB. HTTP эту DB не открывает. Runtime не мигрирует: `OpenExistingControl` требует актуальную schema; explicit init — отдельный trusted шаг.

Enqueue под SQLite write lock: fixed actor/node, exact envelope validation, idempotency(actor,key) + SHA256(node,canonical intent без operation ID), expected observed node revision. Replay возвращает исходную операцию даже после изменения ревизии. Другой payload/node с тем же ключом конфликтует. Stale enqueue → ErrConflict (будущий HTTP412, endpoint пока отсутствует). Enqueue не меняет observed revision.

Claim сериализует мутации узла между DB handles, срок1–60s; runner использует5s. Revoke опережает queued Ensure, но не прерывает уже running операцию. Истёкший running/reconciling получает новый attempts fencing counter и обязательно обрабатывается раньше новых queued. Claim до expiry → ErrLease. Checkpoint `before_apply` commit предшествует fake runtime change. Queue timeout не отменяет серверную операцию.

FakeAgent идемпотентно записывает synthetic peer delta, observed revision и operation/request-hash evidence одной транзакцией. Это только fake atomicity, не гарантия сети. Reconciler после потери ответа сначала ReadState; если результата ещё нет, повторяет тот же intent. Complete сам проверяет durable fake observation, request hash, node/revision и текущий lease/attempt: success response без evidence недостаточен. Checkpoint становится `observed` лишь вместе с terminal state. Старый attempt не завершает работу нового.

Отзыв добавляет append-only tombstone при enqueue; это намерение отзыва, **не доказательство runtime revoke**. Оно подавляет queued/future Ensure того же generation даже до применения. Revoke, уже прошедший expected-revision admission, безопасно применяется к current revision после предыдущей running операции; это явное rebase только монотонного удаления, не stale issuance. Ensure после изменения revision завершается failed/revision_conflict. Повтор runtime request возвращает прежнее evidence, не новую мутацию. Новые generation не считаются отозванными автоматически.

## Пределы

Нет public/admin operation HTTP API, production bridge, worker daemon scheduler/backoff/heartbeat, cancel/rotate/restore/revision validation, IP/key allocation, actual AWG/Xray adapters, network rollback/crash phases, profile ready/download или gateway pairing. Runner делает один step; при неопределённости сохраняет lease/pending для повторной сверки. Не трактовать синтетическую revision как running core attestation.

В среде разработки AF_UNIX socket creation возвращает EPERM. Два transport/integration tests отмечены SKIP только для этого ограничения; required acceptance запускается с `FVPN_REQUIRE_UNIX=1`, тогда EPERM — FAIL. In-process fault/concurrency tests выполнены отдельно. G2 не закрыт.
