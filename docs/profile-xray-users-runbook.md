# Частичная сверка Xray users · v0.23.0

profile-observe-xray-users — trusted local Linux read-only CLI. Требует существующий private portal state и отдельный profile key, импортированный pending VLESS/REALITY profile, independently inventoried loopback API/tag и SHA256 fixed /usr/bin/xray. Public/admin HTTP не загружают ключ и не выполняют этот adapter. Команда не создаёт API, не меняет config/routing/firewall и не выполняет deployment.

## Запуск на согласованном стенде

```sh
./build/vpnctl profile-observe-xray-users \
  --root var/auth --profile-key var/profile-secrets/current.key \
  --owner-id OWNER_ID --device-id DEVICE_ID --profile-id PROFILE_ID \
  --generation 1 --expected-revision CURRENT_REVISION \
  --api-server 127.0.0.1:10085 --inbound-tag INVENTORY_TAG \
  --expected-tool-sha256 INDEPENDENT_LOWERCASE_SHA256 \
  --expected-boot-id INDEPENDENT_CURRENT_BOOT_UUID \
  --expected-netns-device INDEPENDENT_NETNS_DEVICE \
  --expected-netns-inode INDEPENDENT_NETNS_INODE \
  --expected-inventory-sha256 INDEPENDENT_EXACT_BYTE_INVENTORY_SHA256
```

Placeholders заменить актуальными independently protected inventory/target values. Boot UUID canonical lowercase/nonzero, namespace device/inode положительные; missing/malformed значения отклоняются до key/DB/tool. Scope читается из fixed proc paths на locked OS thread до/между/после readbacks. Совпадение loopback address в другом namespace не принимается. Нет expected-value autodiscovery или namespace switching. SHA не получать из недоверенного executable как автоматическое доверие. Loopback допускается только canonical numeric 127.0.0.1 или [::1]; DNS/public/unspecified/mapped/zone addresses отвергаются. Fixed tool regular/root-owned, без symlink/group-world write; иной install path пока unsupported. API/command availability следует проверить для pinned version отдельно. В этой поставке native stand не запускался.

## Как читать результат

Two readbacks проверяются bounded parser и приватным canonical digest; разные JSON/map ordering не считаются drift. В отчёт входят только source, timestamps/TTL60s, user_observed/user_matches, safe field names и явно false acceptance flags. Нет UUID/email/URI/pbk/содержимого readback/target/pin/binding. Хранилище повторно проверяет current ownership/generation/revision/state/key/AEAD/client format/uniqueness/exact bytes/TTL после runtime calls.

credential_unobserved означает, что точный UUID не наблюдался в этом неполном ответе. Это не отсутствие или подтверждённый revoke. credential_alias означает другой exact UUID с совпавшей Xray wire identity; flow — несовпавший выбранный flow. EnumerationComplete/CoreIdentityVerified/RevisionVerified/TransportVerified/ClientsVerified/Ready всегда false. API читается insecure на loopback: pin CLI не удостоверяет responder. REALITY key/SNI/shortId/endpoint и actual handshake/routing этой командой не проверяются.

Даже user_matches:true даёт status:blocked и exit1. Runtime read failure/drift/malformed response/stale binding даёт sanitized status:error/exit1. Никакого implicit exit0 permission. Нельзя передавать --apply/--ready/--input/--tool/client checkbox; snapshot constructor остаётся configuration-only. CLI не пишет ledger/audit/state/revision/installed_revision и не разрешает download. При новых bindings/core/tool/parser revisions нужен новый actual readback. TTL не является current core revision или lease.

KUK-5 остаётся In Progress: полный runtime/core/client/audited transition ещё требуется. Partial Xray Result имеет отдельный тип и не принимается AWG readiness preparation. Keyless profile-readiness unchanged. Source contract/ADR-0017 фиксируют отсутствие complete enumeration и responding core identity; manual forced ready запрещён.

v0.20: оба Linux observer ограничивают также ожидание inherited stdout/stderr: отдельная process group, SIGKILL при отмене, WaitDelay200ms и cleanup после раннего parent exit. Неполный/ошибочный readback очищается и не становится proof. Local helper-process regression tests не являются AWG/Xray native acceptance. Fixed descriptor/pin/args, pending gate, schemas6/4/1 и UI/API сохраняются. ADR-0018, iteration-20.

v0.22: partial Xray users Result теперь связывает independently expected boot ID/netns device+inode с API server/tag/tool pin/current profile/revision/exact bytes/TTL. Observe сверяет fixed proc environment на locked OS thread перед/между/после двух readbacks. Общий internal/runtimeenv используется AWG и Xray; AWG scope/guards сохранены. ExecutionScopeBound относится только к области исходного выполнения; Enumeration/CoreIdentity/Revision/Transport/Clients/Ready остаются false. Snapshot/JSON не приобретают native scope; storage read-only, blocked/exit1, profiles pending. Native/core/client/transition acceptance открыта; схемы6/4/1 без миграции. ADR-0020, iteration-22.

RUNTIME_ENVIRONMENT_CHANGED — unavailable или изменившийся scope; safe report не печатает inventory values. execution_scope_bound:true относится к исходному выполнению, не к responding core identity или свежему runtime recheck. Native wrong-namespace entry и local proc test проверены; injected positive reader не native Xray execution.

v0.23: Xray Observe требует exact-byte independently expected InventorySHA256 для fixed protected /etc/family-vpn/xray-inventory.json. Closed version1 JSON содержит expected boot/netns/kernel release и до16 API/tag/tool/core/config revision expectations. Linux descriptor walk проверяет root ownership/permissions/no symlink/hardlink/special files/64KiB bounds и metadata до/после чтения. CLI проверяет manifest до key/DB; observer повторяет inventory перед/между/после reads. Immutable Result/Check/store target связывает inventory pin; inventory_bound относится к исходному выполнению. Declared core/version/config/kernel metadata не observed core attestation: full Xray acceptance flags false, blocked/exit1, read-only/no ledger/state/audit writes. AWG contract и схемы6/4/1 сохранены; native/core/client/transition acceptance открыта. ADR-0021, xray-inventory-runbook, iteration-23.

Обязательный fixed inventory должен быть отдельно provisioned trusted operator, contract: xray-inventory-runbook.md. Expected core/kernel/tool/config metadata не наблюдаются по этим labels и не включают full acceptance flags.
