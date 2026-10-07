# Итерация22 · v0.22.0 · 05.10.2026

## KUK-5 / M1-02 / DEV-08

Partial Xray named-users Result теперь связывает independently expected boot ID/netns device+inode вместе с API server/tag/tool SHA/current profile/revision/exact bytes/TTL60s. Linux Observe закрепляет OS thread и сверяет fixed proc scope перед/между/после двух bounded readbacks. Missing/malformed scope отвергается до key/DB/tool; environment unavailable/drift/cancellation fail closed, buffers очищаются. Нет expected-value autodiscovery, namespace switching или изменения сети.

Shared internal/runtimeenv выделяет fixed proc reader/canonical boot validator из AWG. Existing AWG Target/Observe/Record/Prepare/fenced Recheck contract сохранён. Xray immutable Check и read-only store recheck требуют тот же expected Target; snapshot только zero target, JSON не восстанавливает Result. ExecutionScopeBound:true характеризует область исходного выполнения. Responding CoreIdentity/Revision/Transport/Enumeration/Clients/Ready false; insecure loopback API/tool pin не удостоверяют responder. No ledger/audit/state writes, no readiness/installed_revision changes; blocked/exit1, pending download gate. Схемы6/4/1 без миграции. ADR-0020/runbook описывают обязательные inputs и ограничения.

## Проверки

Final npm run check PASS: Go vet/race всех packages, API generation без drift, Svelte0 errors/warnings, Vite. npm run build PASS: frontend +6 Go binaries. Persistence/intents smoke PASS; gofmt clean. UI/API/tests22 byte-identical к v0.21; Go dependencies unchanged, новый browser E2E не запускался. Parser не менялся, fuzz не повторялся.

New regressions: independent scope required, changed boot/netns dev/inode/server/tag/tool target rejected; unavailable/drift scope до/между/после readbacks, cancelled before/after reads, buffers clear; snapshot/JSON не приобретают native execution scope; redaction/immutability; CLI missing/malformed scope before owner/key/DB validation; store snapshot scope relabelling rejected without audit/state changes, profiles pending/download blocked. Initial full check обнаружил unkeyed literal existing AWG test после external shared-type alias; исправлены имена полей, final full check PASS.

Actual local read-only proc test подтверждает stable boot/current calling thread namespace stat; actual native Observe entry rejects wrong namespace before fixed Xray tool/API. Positive reader/environment tests injected. Actual Xray binary/API/responding core, AWG tool/core/interface, pinned client/export-import/handshake/DNS/routing и network acceptance не выполнялись; namespace switching не проверялось.

TestPeerUIDAndStrictSocketBody и TestSocketApplyLostResponseThenReconcile подтверждённо SKIP из-за AF_UNIX restriction. Native Unix acceptance с FVPN_REQUIRE_UNIX=1 отдельно. Original63 work/dependency/acceptance text автоматически сравнены без изменений; statuses45 Backlog/15 In progress/3 Verification/0 Done, GW8Backlog. Auth extras Deferred.

## Синхронизация и следующий шаг

Existing KUK-5/project/M1 обновлены и read back: v0.22.0/snapshot1.17. Original Acceptance/relations/IDs/status In Progress и четыре unchecked native AWG/Xray/client/audited transition пункта сохранены. KUK-6/7 delivery ждут полноценного runtime/client evidence; G1 открыт. No assignee/new issue/M2/M3/messages/VPS/deploy/GitHub remote CI actions. Archive excludes state/keys/dependencies/build/research/helpers.

Далее responding-core/protected inventory/current revision и actual approved stand/client attestor. Execution location не заменяет эти доказательства; future audited transition повторяет guards/current proof со state/audit в одной writer transaction. Local recheck не lease.
