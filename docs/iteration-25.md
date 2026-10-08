# Итерация25 · v0.25.0 · 08.10.2026

Продолжается KUK-5/M1-02: selected-peer AWG session diagnostics перед actual core/client acceptance. Нативные VPN-ядра и Android в этой Windows среде не запускались. G1, readiness transition и выдача рабочих конфигов остаются открытыми.

## Входы владельца

07.10 владелец сообщил о работающем user/admin входе на RU. Есть два сервера Ubuntu20.04/~1GiB, Foreign пока не настроен, VPN не установлен, первый клиент Android. Это owner-reported smoke, не независимое обследование/QA. Architecture/kernel/tool/core versions и Android app/build ещё не измерены. Никаких VPS, SSH/firewall/routes или public deployment действий из этой задачи не выполнялось.

## Реализация

Новая trusted `profile-observe-awg-session` читает fixed pinned root-owned `/usr/bin/awg`: named-interface `latest-handshakes`/`transfer`, двухсекундный cancellable interval, ещё два чтения. Независимый boot/netns проверяется до/между/после, namespace не меняется. Сохраняются pinned descriptor, bounded stdout/process-group/pipe cleanup и общий12s timeout CLI. Closed command vocabulary исключает mutation, dump, interface discovery и произвольный executable. Showconf observer сохраняет прежнюю семантику.

Closed parser ограничивает64KiB/256rows, canonical keys/unsigned decimal values/UTC timestamp, duplicate rows/columns/future times и peer/counter/handshake drift. Selected identity выводится из validated client private key с clamping; raw keys/counters в отчёт не попадают. Frozen client bytes, cleared readback buffers, deep-copied timestamp и opaque JSON сохраняют immutable exact-byte/profile/revision/expected target binding. Lifetime не больше60s от начала чтений. Recent window180s — диагностическая политика, не гарантия активного клиента.

Store после чтений повторяет current owner/device/profile/generation/revision/pending/null installed guards, current purpose key, AEAD, format, credential uniqueness и sealed TTL/bytes/target в read transaction. Нет DB state/audit/observation ledger writes; SQLite read-only может обслуживать WAL/SHM. `SessionResult` отдельный от configuration `Result`, не попадает в `RecordProfileObservation`/readiness candidate. CLI не принимает apply/input/snapshot/tool/client-ready flags; всегда blocked/exit1, core/revision/client/DNS-routing/ready false. Keyless profile-readiness и HTTP repositories/UI/auth/API generation не изменены.

Runbook profile-awg-session-runbook.md и ADR-0022 описывают границы. Linux bundle также включает этот runbook. Protected expectations не выдаются за installed-core/loaded-revision attestation; existing AdvancedSecurity requirement не ослаблен.

## Проверки

- Windows targeted Go tests:15 top-level tests PASS в clientconfig/profileobserve/store/vpnctl, включая malformed/oversized/duplicate/future/regression/clamping, scope/cancellation/buffer cleanup, exact-byte mutation/JSON forgery, current storage/AEAD/key rotation/uniqueness и CLI rejection/no state creation.
- Полные доступные Windows packages profileobserve/store/runtimeenv PASS. Linux-only observerexec не выполняется на Windows; direct package invocation сообщает build constraints, не PASS.
- `npm run build` PASS: Svelte0 errors/warnings, Vite и6 Go executables. Built Windows CLI rejects `profile-observe-awg-session --apply` с sanitized JSON/exit1, no readiness.
- API generation unchanged PASS; Windows CGO0 Go vet и Linux amd64 CGO0 cross-target Go vet PASS. Linux profileobserve test binary compile PASS, execution не выполнен.
- `npm run test:release` PASS8/8. Linux amd64/arm64 bundles cross-build PASS; независимый Python tar reader подтвердил11 closed files, ELF64 arch62/183, executable0755, file/manifest/SHA256SUMS/external checksums и false acceptance metadata. State/credentials/TLS keys/control binaries в пакетах отсутствуют. Runtime Linux execution не выполнен.
- `npm run check` NOT PASS: default CGO0 не поддерживает race; с явным CGO1 отсутствует gcc. Full race/check не заявляется успешным.
- Независимый read-only code review не выявил actionable defects. UI/auth flow source не менялся, E2E в v0.25 не повторялись; ограничения исторических suites сохранены в iteration-24.

## Статусы и следующий шаг

Snapshot1.20 обновлён в основном backlog и локальных milestone/roadmap/next-iteration. Original63 work/dependencies/acceptance сохраняются:45 Backlog/15 In progress/3 Verification/0 Done; GW8Backlog. Linear/remote Git/CI этой версии не обновлялись. Source archive не содержит Git metadata.

Следующий этап — согласованный изолированный RU→Foreign stand с independently pinned core/tool и Android app/build; actual configuration readback/Android import/handshake/DNS/TCP/UDP/IPv6/Foreign-loss/host management acceptance. Затем core/runtime revision fence и client proof проверяются в одной audited writer transaction перед ready/delivery. Handshake/counters, supplied snapshot или ручное подтверждение этого не заменяют. Linux positive native→store/CLI путь и actual Android acceptance этой поставкой не пройдены.

## Артефакты

`family-vpn-starter-v0.25.0.zip` — source package с allowlisted files и SOURCE-MANIFEST.json, без runtime state/keys/caches/SDK. Прежние версии сохраняются. SHA и entry contents проверяются packager после создания. Original63 criteria и normative specification byte hash независимо сверены с source archive v0.24; изменений критериев нет.

Linux runtime bundles: `build/releases/family-vpn-v0.25.0-linux-amd64.tar.gz` SHA256 `6cbbb2e6bc94ef99c282ff8009750998fa4a096a9bfe68f4d9109556e8fe129a`; arm64 SHA256 `740d5d03076dcf002e8819e625869fd89ac5f5f255058d751c0e7ad06b0c5e36`. Это комплект кабинета/CLI, не принятый VPN deploy или pilot RC.
