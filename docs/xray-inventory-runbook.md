# Xray inventory · v0.23.0

Protected manifest — обязательный вход trusted local profile-observe-xray-users. Фиксированный путь /etc/family-vpn/xray-inventory.json; Linux only. Файл и цепочка / → etc → family-vpn должны принадлежать UID0, без group/world write, symlink или special mode bits. Файл regular, non-executable, single hard link, 1..65536bytes. Рекомендуемые modes: directories0755, file0644 либо0640. CLI только читает: provision/atomic replacement inventory — отдельная операция trusted operator на согласованном стенде.

## Version1 contract

Каждое поле обязательное и non-null; exact lowercase field names, unknown/duplicate/case aliases forbidden. Whole JSON имеет единственный объект без trailing document. Строковые expectations не принимают URLs/secrets/config material.

| Поле root | Значение |
|---|---|
| schema_version | JSON integer1 |
| boot_id | independently known current canonical lowercase nonzero UUID |
| netns_device, netns_inode | positive uint64 JSON integers текущего expected netns |
| kernel_release | expected release label1..64 ASCII letters/digits/`.`/`_`/`+`/`-`, first alphanumeric |
| xray | array1..16 complete target objects |

| Поле target | Значение |
|---|---|
| api_server | canonical numeric127.0.0.1:port либо[::1]:port, port>0 |
| inbound_tag | current independent tag1..64 allowlisted letters/digits/`.`/`_`/`-`, no leading dash |
| tool_sha256, core_sha256, config_sha256 | independently expected64 lowercase hex chars |
| tool_version, core_version | expected labels1..64, same lexical contract as kernel_release |

API/tag пары уникальны. Targets с одним api_server требуют одинаковые tool/core/config expectations; несколько tags разрешены. Schema предназначена для Xray expectations, AWG пока использует прежний scope contract. No arbitrary executable/core/config input paths; private keys/UUID/email/export/credentials сюда не помещать. Config digest является expected content revision; текущую загруженную конфигурацию или dynamic API changes этим не подтверждают.

## Observer

К прежней команде из profile-xray-users-runbook добавить --expected-inventory-sha256 INDEPENDENT_EXACT_BYTE_INVENTORY_SHA256. Существующие API/tag/tool/boot/netns flags остаются explicit и должны совпадать с manifest. SHA должен происходить из доверенного независимого inventory; хеширование неизвестного файла на неизвестном host не даёт доверия. Даже whitespace/перевод строки меняет exact-byte pin; после approved replacement требуется новый independently expected pin и новое observation.

Missing/malformed expected pin → INVALID_RUNTIME_TARGET до owner/key/DB. Manifest отсутствует, wrong owner/permissions/type/ambiguous JSON/changed metadata/hash/target → INVENTORY_UNAVAILABLE_OR_CHANGED; report не раскрывает path/hash/values/raw filesystem errors. Env mismatch → RUNTIME_ENVIRONMENT_CHANGED. CLI preflight читает inventory до key/DB; Observe повторяет fixed-file check на locked OS thread перед/между/после readbacks. File descriptors close-on-exec, response/failed inventory buffers очищаются. No setns/unshare/network/config mutations.

inventory_bound:true подтверждает только binding исходного Result к проверенным protected expectations. Kernel/core/tool versions и config digest записаны в manifest как expected metadata; loader не сверяет их с running core/kernel/config. core_identity_verified/revision_verified/transport_verified/enumeration_complete/clients_verified/ready false. Successful named-user match всё ещё status:blocked/exit1; no ledger/audit/state writes, pending/download gate. Store recheck проверяет original immutable Result/expected target, не перечитывает inventory/runtime и не создаёт lease.

Local verification не native VPN acceptance. Actual temporary-file tests verify protected reads/links/FIFO/bounds/mutation; foreign owner policy tested on synthetic stat because sandbox refuses chown to unmapped UID. Native tool/API/core and real clients не запускались. Для full KUK-5 нужны protected responding-core provenance/current config/runtime revision/REALITY evidence, approved native positive+negative stand и client attestor. Manual core_verified/ready flags запрещены.
