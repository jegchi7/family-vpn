# Итерация21 · v0.21.0 · 05.10.2026

## KUK-5 / M1-02 / DEV-08

AWG immutable Result теперь связывает independently expected Interface/Endpoint/ToolSHA256/BootID/NetNSDevice/NetNSInode вместе с current profile binding/revision/exact bytes/TTL60s. Fixed proc environment сверяется на locked OS thread, из которого запускается pinned tool, перед/между/после двух bounded readbacks. Wrong/changed/malformed/unavailable scope и cancellation отклоняются, buffers очищаются. Нет expected-value autodiscovery, setns/unshare/namespace entry, изменения сети или нового tool path.

Result.Check, RecordProfileObservation, PrepareAWGReadiness и writer-fenced RecheckAWGReadiness требуют explicit expected target. Snapshot scope — endpoint/configuration only, не native. Result/candidate JSON не восстанавливает evidence; inventory values не печатаются и не сохраняются в ledger. Keyless readiness добавляет runtime_target_verified:false и mandatory runtime_target_verification_required; historical source/TTL match остаётся диагностикой. Schema6/4/1 без migration. ADR-0019 и updated observation/readiness runbooks описывают новые обязательные CLI inputs.

RuntimeTargetBound означает только область исходного observation, не identity/version actual core/kernel, config revision, interface lease, endpoint reachability или client proof. Recheck не перечитывает runtime, а его fence освобождается при возврате. Future audited transition всё ещё требует protected current inventory и actual client proof в одной writer transaction со state/audit. Profiles pending/download blocked.

## Проверки

Final `npm run check` PASS: Go vet/race всех packages, API generation без drift, Svelte0 errors/warnings и Vite. `npm run build` PASS: frontend +6 Go binaries. `npm run test:persistence` и `npm run test:intents` PASS. Gofmt clean. UI/API/tests22 byte-identical к v0.20; новый browser E2E не запускался. Go dependencies unchanged. Parser не менялся, fuzz не повторялся.

New regressions: interface/endpoint/tool/boot/netns device/inode rebinding; environment unavailable/changed before/between/after reads, cancellation before/after read, cleared buffers, result JSON rejection and redaction, snapshot/native scope separation. Storage record/prepare/recheck target failures не пишут metadata/audit и не открывают download. Keyless fresh historic runtime rows не дают target verification. CLI malformed/missing independent inventory rejected before key/DB/tool reads, safe output. Initial CLI test expected a different existing input error code; assertion corrected to INVALID_TARGET, final full check PASS.

Actual local read-only proc probe confirmed stable boot ID/current locked-thread namespace stat; native Observe entry rejects wrong namespace before accessing the AWG tool. No actual AWG tool/core/interface positive readback, namespace switching, VPS/Xray API/core/client execution or network acceptance. Injected reader/environment tests остаются local contract verification.

TestPeerUIDAndStrictSocketBody и TestSocketApplyLostResponseThenReconcile подтверждённо SKIP/AF_UNIX restriction. Native Unix acceptance с FVPN_REQUIRE_UNIX=1 отдельно. Original63 work/dependencies/acceptance автоматически сравнены без изменений; statuses45 Backlog/15 In progress/3 Verification/0 Done, GW8Backlog. Auth extras Deferred.

## Статусы и синхронизация

KUK-5 In Progress; четыре native AWG/Xray/client/audited transition acceptance пункта unchecked. KUK-6/7 blocked, KUK-19 In Progress, KUK-8 G1 Backlog. Existing KUK-5/project/M1 updated and read back: baseline v0.21.0/snapshot1.16, original Acceptance/relations/IDs unchanged. No assignee/дубликатов/M2/M3 mutations/messages/VPS/deploy/GitHub remote CI. Source archive excludes state/keys/dependencies/build/research files.
