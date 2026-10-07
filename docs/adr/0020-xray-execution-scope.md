# ADR-0020 · Область выполнения Xray users observer

Статус: принято для локального KUK-5, v0.22.0. Полная native/core/client приёмка открыта.

Numeric loopback API address обозначает сокет в текущем network namespace. Два namespace могут иметь одинаковый адрес/порт с разными responders. Поэтому partial users Result должен сохранять independently expected boot ID и namespace st_dev/st_ino вместе с server/tag/tool pin и current profile/revision/exact bytes/TTL60s.

Target.Scope — обязательный runtimeenv.Scope: canonical lower-hex nonzero boot UUID и положительные device/inode. CLI требует --expected-boot-id, --expected-netns-device, --expected-netns-inode без default/autopick. Не получать expected values из произвольного host/tool как автоматическое доверие: их происхождение — independently protected current inventory согласованного стенда.

Linux Observe использует LockOSThread до всех environment/tool calls. Общий internal/runtimeenv читает только fixed /proc/thread-self/ns/net и bounded /proc/sys/kernel/random/boot_id. Exact scope сравнивается перед первым, между и после двух readbacks, до разбора полученных bytes. Unavailable/changed scope/cancellation отвергаются; buffers очищаются. Нет setns/unshare/namespace entry или изменения сети. Existing AWG Target/Observe/storage/preparation/fenced recheck сохраняют прежние guards, shared reader заменяет дублированный proc code.

ExecutionScopeBound:true означает только проверенную область исходного выполнения частичного observer. Это не identity responding core, current config revision, protected API transport, complete enumeration, lease или client attestation. All full acceptance flags остаются false. Result.Check и storage read-only recheck требуют ту же полную target; recheck не перечитывает runtime. Snapshot требует zero Target и имеет ExecutionScopeBound:false; JSON не восстанавливает evidence. Inventory/boot/netns/tool pin не попадают в report/ledger/audit/DB. No new schema, ready/installed_revision mutation, download permission. CLI остаётся blocked/exit1 при совпадении named user.

Local injected environment/reader regressions проверяют scope drift/unavailability до/между/после reads, rebinding, cancellation, очищение buffers и redaction. Local read-only proc probe и native wrong-namespace rejection выполняются без AWG/Xray tool/API. Positive native core/client path не выполнялся; реальные approved manifest/stand/client proof ещё нужны для KUK-5.

Primary contracts: [Linux network_namespaces(7)](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) — isolation network stacks/ports/sockets; fixed proc/namespace identity/boot/Go locked-thread источники закреплены в ADR-0019. Source contract не receipt native VPN acceptance.
