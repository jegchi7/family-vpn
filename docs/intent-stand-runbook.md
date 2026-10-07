# Локальный synthetic agent/queue stand · v0.13

Нужен Linux с разрешёнными Unix sockets; это тест метаданных, не VPN и не управление серверами. Go build нужен заранее. Использовать отдельный пустой state root; не указывать production/demo control DB. DB private0700/0600, socket owner-private0700/0600; controller/agent одного локального UID. По умолчанию executables отказываются работать.

## Запуск

Из корня проекта после `npm run build`:

```sh
umask 077
mkdir -p var/control-stand var/agent-stand
chmod 700 var/control-stand var/agent-stand
./build/hop-controller --fake-stand --command init
./build/node-agent --fake-stand --socket "$PWD/var/agent-stand/agent.sock" --allow-uid "$(id -u)"
```

В другом терминале, в том же корне, передать JSON через stdin. Это не VPN credentials: только synthetic IDs.

```sh
./build/hop-controller --fake-stand --command enqueue --idempotency-key request-demo-1 <<'JSON'
{"schema_version":1,"operation_id":"operation-demo-1","type":"EnsureDeviceProfiles","target_id":"synthetic-profile-1","expected_revision":0,"payload":{"generation":1}}
JSON
./build/hop-controller --fake-stand --command step --socket "$PWD/var/agent-stand/agent.sock"
./build/hop-controller --fake-stand --command status --operation-id operation-demo-1
```

Повтор enqueue с тем же idempotency key/payload возвращает тот же operation ID и terminal state. Для следующего нового intent использовать current observed revision: после этого примера1. Другой payload с тем же key → `idempotency_conflict`; stale revision → `revision_conflict`. JSON report содержит только operation/node/state/code/attempts/checkpoint и optional observed_revision при наличии fake evidence, без envelope/configs. Это revision конкретной операции, не гарантия свежести текущего состояния узла. ReadState используется runner для ранее сохранённой операции, не как произвольный query API.

Step выполняет одну операцию; worker продолжает очередь в foreground. После сбоя или отсутствующего ответа операция остаётся running; повтор после10s lease начинает reconciling. Проверить status, устранить недоступность agent и выполнить step снова после next_attempt_at (delays2..60s). Worker повторяет unresolved intent с ограниченной частотой и не завершает его по счётчику; автоматического сетевого fallback нет. Нельзя считать зависшую операцию завершённой только из-за timeout. Синтетический runtime сохраняется в той же control DB; actual production state так хранить нельзя.

SIGTERM/Ctrl+C закрывает agent. Если процесс убит без cleanup, existing socket path намеренно блокирует запуск; после проверки отсутствия старого процесса удалить только собственный stale socket. Не делать `rm -rf` state или прямую SQL правку очереди в эксплуатации. Fault injection SQL используется исключительно тестами.

## Проверки

```sh
go test -race -v ./internal/agentprotocol ./internal/store ./internal/reconciler
FVPN_REQUIRE_UNIX=1 go test -race -count=1 -v ./internal/agenttransport ./internal/reconciler
```

Вторую команду выполнить на разрешённом Linux стенде: native UID denial, body/field bounds, path ownership и lost-response через actual Unix transport. ENV flag делает socket EPERM ошибкой, а не skip. В текущем окружении AF_UNIX запрещён; перенос проверок на TCP не доказывает Unix security boundary.

Перед real adapter work нужны отдельные public/management/agent UID и проверка запрета public→control DB/socket, PRE/NET network stand, независимый runtime observer и trusted desired payload generation. Control migration3→4 выполняется только explicit trusted init/open, существующие revisions/operations/gateway metadata сохраняются. `docs/adr/0010-local-intent-queue.md` описывает пределы.

## Worker, просмотр и отмена

После explicit `init` (обновляет stand DB3→4) и запуска node-agent:

```sh
./build/hop-controller --fake-stand --command worker --socket "$PWD/var/agent-stand/agent.sock" --poll-ms 500
```

В другом терминале:

```sh
./build/hop-controller --fake-stand --command list --limit 25
./build/hop-controller --fake-stand --command list --state reconciling --limit 25
./build/hop-controller --fake-stand --command cancel --operation-id operation-demo-1
```

Cancel успешен только если Ensure ещё queued/attempts0; уже запущенный пример выдаст conflict. Revoke отменить нельзя. Повтор cancel идемпотентен, cancelled idempotency replay не воскресает. Это отмена synthetic операции, не VPN-отзыв и не Device cancellation endpoint.

Для следующей страницы передать `--after N` из `next_cursor`; limit1..100, live sequence pages. Metadata не содержит request hash/key/envelope. `next_attempt_at` означает persisted UTC deadline повторной сверки; `last_error_code` — fixed code без backend details. Unknown outcome блокирует новые мутации этого узла до observed reconciliation. Retry count не означает successful/failed runtime и не создаёт ready profile.

Worker работает foreground до Ctrl+C/SIGTERM, report только при результате/отложенном attempt, idle не печатается. Poll100..5000ms, operation context8s/lease10s. После отменённого call остаётся durable pending; bounded1s запись retry допустима перед exit. При crash до journal expirylease восстанавливает reconcile. При clock jumps deadlines следуют UTC времени хоста; требуется корректное время. ADR-0011 описывает ограничения.
