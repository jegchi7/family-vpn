# ADR-0019 · Область AWG runtime observation

Статус: принято для локального KUK-5, v0.21.0. Native AWG/core/client acceptance открыта.

До v0.21 immutable AWG Result связывал owner/device/profile/generation/revision и exact client bytes, но не сохранял интерфейс/tool pin/runtime environment как обязательную область последующей проверки. API storage/readiness также не требовал независимо выбранную target. Профили при этом оставались pending; проблема относится к подготовке future runtime evidence.

Target теперь включает Interface, Endpoint, ToolSHA256, BootID, NetNSDevice и NetNSInode. Native Observe требует полную валидную target до чтения tool; pin — 64 lower hex, boot UUID — canonical lower hex nonzero, namespace numbers positive. Endpoint lexical validation переиспользует existing AWG subset и не выполняет DNS lookup. Target остаётся private внутри Result/candidate; отчёты не печатают inventory, pins, boot/namespace IDs, client material или raw errors.

Native Observe закрепляет goroutine через LockOSThread. На том же потоке, из которого запускается pinned tool, читаются fixed /proc/thread-self/ns/net и bounded /proc/sys/kernel/random/boot_id. Независимо ожидаемые boot + namespace st_dev/st_ino сравниваются перед первым, между и после двух readbacks. Ошибка/смена/cancellation отклоняет результат, buffers очищаются. Нет setns/unshare/namespace entry, настройки интерфейса, RPC probes или автоматического определения ожидаемых inventory значений.

Result.Check, RecordProfileObservation и PrepareAWGReadiness требуют explicit independently supplied target. Candidate хранит её, RecheckAWGReadiness снова требует target и отвергает изменение; writer-fenced helper повторяет Result.Check вместе с прежними AEAD/current binding/format/uniqueness/bytes/TTL guards. Fence заканчивается при возврате, не lease/permission. Recheck не перечитывает runtime; RuntimeMatches/RuntimeTargetBound относятся к исходному observation. Будущий transition обязан получить current protected inventory и actual client evidence, повторить всё со state/audit в одной writer transaction.

Snapshot содержит только endpoint scope; его нельзя привязать к native target или получить runtime_target_bound:true. JSON cannot restore Result/candidate. Ledger schema6 хранит прежнюю safe историческую metadata, без target identity/secret digest; migrations не нужны. Keyless profile-readiness сохраняет runtime_target_verified:false и новый blocker runtime_target_verification_required, включая old/new fresh ledger rows. StoredRuntimeReadbackFresh означает только metadata age/source/binding, не attestation target.

Boot/namespace scope не доказывает identity/version responding AWG core/kernel, config revision, lease интерфейса, endpoint reachability, handshake/DNS/routing или client compatibility. Protected inventory/actual manifest/stand всё ещё требуется, snapshot/fake checkbox не делает ready. Native positive path на AWG не выполнялся. Проверки используют injected readback/environment и отдельный actual local read-only proc probe; namespace switching не проверялось.

Primary contracts inspected 05.10.2026:

- [Linux namespaces(7)](https://man7.org/linux/man-pages/man7/namespaces.7.html): namespace identity via st_dev/st_ino.
- [Linux proc thread-self](https://man7.org/linux/man-pages/man5/proc_thread-self.5.html): calling thread, not just process leader.
- [Kernel sysctl random](https://cdn.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#random): boot_id stable for the boot; it is not uuid generated for every read.
- [Go1.27.1 os.StartProcess](https://pkg.go.dev/os#StartProcess), [runtime.LockOSThread](https://pkg.go.dev/runtime#LockOSThread): locked thread/inherited thread state.

Source documentation is not a native VPN acceptance receipt.
