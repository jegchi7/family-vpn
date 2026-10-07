# ADR-0013 · Scoped AWG readback без автоматической готовности

Статус: принят для локального среза v0.15.0 · 05.10.2026. Родители: M1-02, PRE-04, DEV-02/08. Native operational acceptance остаётся открытым.

## Решение

Trusted CLI читает только именованный интерфейс текущего netns через fixed root-owned `/usr/bin/awg`, independent SHA-256 pin и открытый file descriptor. Два ограниченных readbacks должны совпасть. Нельзя передать произвольный executable или назвать snapshot bytes runtime observation. Snapshot constructor помечает результат `awg-snapshot`; native constructor — `awg-runtime`. Positive native execution пока не проверен на настоящем ядре/бинарнике.

Result закрыт от внешнего изменения, имеет random ID, TTL60s, exact owner/device/profile/generation/revision/client-byte binding. Summary содержит только безопасные имена полей и timestamps; snapshot/server private key не сохраняется. Portal migration6 добавляет metadata ledger. Запись результата и audit атомарны, повтор ID не создаёт второй audit; транзакция заново проверяет current binding, состояние и plaintext. Истечение TTL не стирает историческую запись и не делает её действительным разрешением на выдачу.

Readback относится к наблюдаемой конфигурации AWG, а не к handshake/client success. Он не устанавливает `ready`, `installed_revision` или address allocation. После измерения runtime может измениться; atomic native revision/fencing и ongoing validity требуют следующего контракта. Portal/admin HTTP не получают ключ, native tool, control DB или privileged bridge. Binary pin не заменяет доверие к host/root/kernel и подтверждение версии.

## Последствия

Snapshot/injected-read tests дают воспроизводимые parser/transaction проверки; они явно отделены от native positive acceptance. Закрытая allowlist намеренно может отвергнуть ещё не исследованные native fields/hex FwMark. Client local obfuscation/timers/CPS не приравниваются автоматически к server wire settings. Нет установки бинарника, namespaces/container adapters, сетевых writes/probes или deployment templates. Readback и его совпадение не разрешают переход к DEV-09 без remaining M1-02 client/runtime acceptance.
