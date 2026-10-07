# ADR-0011 · Foreground worker, durable retry и queued cancellation

04.10.2026 · принято для synthetic local stand. Дополняет ADR-0010, не снимает production gates.

## Retry и неизвестный результат

Control migration4 добавляет `next_attempt_at`, bounded consecutive failure counter0..30 и allowlisted last error code. После неопределённого результата runner записывает `reconciling`, освобождает текущий lease, сохраняет время следующей попытки и не ставит terminal state. Задержки2/4/8/16/32/60s, далее60s; retry count сам по себе никогда не означает success или окончательный failure. Attempts сохраняет fencing counter, consecutive failures ограничивает backoff counter. Успешная observed completion очищает retry metadata; ранее принятую ревизию не меняет.

Новый claim учитывает persisted deadline. До него → ErrRetryLater; после — reconcile старого intent до любой новой мутации узла, включая queued revoke. При неизвестном применении запрещено обогнать старую операцию: иначе поздний Ensure мог бы вернуть отозванный peer. Результат read проверяется storage completion, не доверяется success DTO. Runtime Observe остаётся fake из ADR-0010; real agent observer отдельно.

Wall-clock UTC deadlines сохраняются между процессами; требуется корректное время на хосте. Не обещать monotonic clock across reboot или отсутствие влияния clock jumps. При crash до записи retry остаётся lease: после истечения он также ведёт к reconciling. После crash после runtime commit/до queue completion read восстанавливает результат без второго apply.

## Worker

`hop-controller --fake-stand --command worker` запускает foreground loop одного fixed node. Poll100..5000ms (default500), operation context8s, claim lease10s. Нет unbounded goroutine pool; параллельные worker сериализуются writer transaction/lease. Не использовать scheduler для установки ядер/сетевых shell commands. В stdout только typed operation metadata; ошибки backend никогда не сериализуются. Idle/busy/not-yet-due не создают log flood. Uncertain failures report once per attempt и сохраняют pending, storage errors прекращают worker.

SIGTERM/Ctrl+C отменяет контекст, останавливает loop и не отменяет persisted операцию. После отменённого backend call допустима только bounded1s retry journal write через WithoutCancel: ни нового claim, ни нового apply. Применение, пропустившее lease, не получает completion; next executor сверяет observed state. No heartbeat: длинные real adapter операции требуют отдельной lease/fencing модели.

## Отмена и метаданные

Trusted cancellation actor/node-scoped, idempotent. Разрешён только Ensure в queued с attempts0/checkpoint=intent и без fake evidence. Claim/cancel конкурируют под writer lock, выигрывает один. Running/reconciling/terminal выдача не отменяется этой командой. **Revoke нельзя отменить**, даже queued: его append-only tombstone уже записан при admission. Cancellation не удаляет generations/tombstones, не отзывает действующий VPN-профиль. Replay idempotency key возвращает cancelled operation, не воскресшую queued.

Trusted `list` выполняет read-only SQL, bounded1..100 и sequence keyset cursor, optional allowlisted state. Это live pages, не snapshot: изменения фильтра между страницами могут изменить состав. Safe DTO не содержит actor/idempotency key/request hash/envelope/config/path/credentials. List/status работают через trusted CLI с private control DB; public/admin HTTP не получают эту DB. HTTP read model/bridge потребует отдельной архитектуры.

## Приёмка и пределы

In-process fake tests и реальный CLI process restart проверяют durable retry, cancel/claim race, node serialization, no false success/no error leakage и bounded shutdown. Native AF_UNIX/UID tests всё ещё требуют разрешённого Linux стенда. Не считать это actual VPN revoke, production queue integration, gateway rotation или подтверждённым recovery сети. No profile ready/download from fake evidence.
