# Итерация23 · v0.23.0 · 06.10.2026

## KUK-5 / M1-02 / DEV-08

Введён protected expected Xray inventory: единственный Linux read-only path /etc/family-vpn/xray-inventory.json, mandatory independently expected exact-byte SHA256. Closed version1 JSON связывает expected boot/netns/kernel release и1..16 numeric-loopback API/tag targets с tool/core versions/digests и config digest. Все поля обязательны, non-null; parser rejects duplicate/case aliases/unknown fields/trailing JSON/invalidUTF8/depth>8/size>64KiB/count>16/invalid scope/pins/labels/duplicate targets/inconsistent core/tool/config per API.

Fixed-path Linux loader открывает каждый компонент через checked directory descriptor и O_NOFOLLOW/O_CLOEXEC/O_NONBLOCK. Root UID0, no group/world write/special modes; file regular/non-executable/single-link/bounded. Before/after metadata/type/inode/permissions/ownership/size/mtime/ctime/path links checked, failure buffers clear. Не caller-selected path, expected-value autopick или hostile-root/kernel isolation. Local trusted filesystem assumption; byte bounds не гарантируют прерывание зависшего filesystem syscall.

Xray Target добавляет InventorySHA256; Result/Check/read-only storage recheck immutable bind новой expected revision вместе с прежними server/tag/tool/boot/netns/profile/revision/exact bytes/TTL60s. CLI manifest validation выполняется до key/DB; locked-thread Observe повторяет environment и fixed-file inventory перед/между/после двух readbacks. inventory_bound:true относится к исходному observation/ожиданиям; snapshot zeroTarget/inventory_bound:false, JSON cannot restore evidence. New error safe INVENTORY_UNAVAILABLE_OR_CHANGED, no inventory raw path/values/digest/core labels in output/ledger/audit/state.

Declared core/tool/kernel version и config digest — expected metadata, не observed runtime/core identity/current revision. Full Enumeration/CoreIdentity/Revision/Transport/Clients/Ready flags false, CLI blocked/exit1, profile pending/download blocked, no ledger/audit/state writes. AWG scope/readiness/keyless diagnostics unchanged, schemas6/4/1 без migration. ADR-0021/runbooks фиксируют provenance/limits и обязательный flag.

## Проверки

Final npm run check PASS: Go vet/race всех packages, API generation без drift, Svelte0 errors/warnings/Vite. Build PASS: frontend +6 Go binaries. Persistence/intents smokes PASS. Inventory fuzz target5s/15965 executions PASS; actual fuzz elapsed6.015s. Gofmt clean. UI/API/tests22 byte-identical к v0.22; dependency versions/go.sum unchanged, existing x/sys v0.48.0 теперь direct import. Новый browser E2E не запускался; users parser не менялся.

New parser/target/pin/rebind/immutability/redaction guards; missing/malformed inventory pin rejected before owner/key/DB; missing/mismatched fixed inventory rejected before nonexistent key. Injected unavailable/changed inventory before/between/after API reads and cancellation reject Result and clear response buffers. Read-only store snapshot target relabelling rejected, no metadata/audit/state changes, ready download remains blocked.

Actual local temporary-file descriptor tests verify protected root-owned reads, permissions/executable mode, symlink file/parent, hardlinks, directory/FIFO instead of file, empty/oversize, replacement/content/mode changes/cancel/read error; fixture paths confined to temporary directories. Initial test attempted actual chown to foreign UID65534; sandbox rejects it with invalid argument (unmapped UID). Final owner policy negative tests use synthetic stat; no claim actual foreign-UID filesystem acceptance. No host /etc inventory provisioning/network mutation.

Existing actual local read-only proc/native wrong-namespace entry tests PASS; positive observer inventory/readbacks injected. Actual AWG/Xray tool/API/responding core/version/config/REALITY transport and real client export-import/handshake/DNS/routing acceptance не выполнялись. Two Unix tests TestPeerUIDAndStrictSocketBody/TestSocketApplyLostResponseThenReconcile подтверждённо SKIP/AF_UNIX restriction; native UID/socket acceptance с FVPN_REQUIRE_UNIX=1 отдельно.

## Статусы и синхронизация

Existing KUK-5/project/M1 updated and read back: baseline v0.23.0/canonical1.18. Original Acceptance/relations/IDs/status In Progress и четыре unchecked native AWG/Xray/client/audited transition пункта сохранены; M2/M3 descriptions/milestones unchanged. Original63 task/dependency/acceptance text автоматически сравнены без изменений; statuses45 Backlog/15 In progress/3 Verification/0 Done, GW8Backlog; auth extras Deferred. KUK-6/7 delivery blocked, G1 открыт. No new issues/assignees/messages/VPS/network config/deploy/GitHub remote CI actions.

Next: protected expectations должны быть связаны с actual responder/core/current revision и client attestor; audited transition повторяет guards/proof со state/audit в одной writer tx. Inventory pin/root ownership не подписывают responder, store recheck не fresh runtime/inventory read или lease. Source archive excludes state/keys/dependencies/build/toolchain/research/helpers.
