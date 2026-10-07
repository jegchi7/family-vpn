# AWG showconf contract · v0.17

Проверен формат исходников upstream 05.10.2026. Это source inspection, а не запуск AWG, независимый runtime inventory или совместимость клиентов. В поставку не включён upstream source; fixtures генерируют ключи в test memory. Никаких VPS, интерфейсов, routes или firewall при исследовании не меняли.

| Источник | Commit | SHA-256 файла | Проверенная граница |
|---|---|---|---|
| [amneziawg-tools src/showconf.c](https://github.com/amnezia-vpn/amneziawg-tools/blob/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843/src/showconf.c) | ee0f0a9aa34ff0a0da4b3433b9512781cfe02843 | 3dfa3ab971fc76e5339f28f806f694b223af6710d8358a035e4d7a90b28b083c | Nonzero FwMark выводится hex; AdvancedSecurity печатается только при WGPEER_HAS_AWG |
| [amneziawg-go device/uapi.go](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/uapi.go) | b5928efb6ca19f0153958460c3d141f04abc5c2e | 7a88ac0cc50ea932336042d963183760e38a48fd8e055e0c0d00a4324cf1ef32 | bool device modes сериализуются; per-peer AdvancedSecurity не выдаётся в inspected IpcGetOperation |

Эти commit/hash идентифицируют рассмотренный source, не SHA pin установленного executable. Manifest actual stand всё ещё должен независимо фиксировать binary SHA, core/version, kernel, netns, interface, expected endpoint и client app/build/format. Источник snapshot нельзя переименовывать в runtime. Native adapter остаётся fixed /usr/bin/awg и two identical bounded readbacks; injected reader не native acceptance.

## Локальный контракт сравнения

- Selected peer определяется derived client public key. Explicit AdvancedSecurity=on требуется для положительного match этого M1 AWG3.1 subset. Off или отсутствующее поле возвращают advanced_security conflict; неизвестность не считается on. Другой peer не сертифицирует выбранный. Это conservative evidence policy, не утверждение о wire semantics всех версий AWG.
- RandomTrailers/DisableCookies сравниваются симметрично: omission=off. Так client omission не скрывает server on. Это сохраняет прежнюю matching policy, не заявляет невозможность соединения при любом отличии на произвольном core.
- Readback FwMark ограничен off/decimal uint32/0x с1…8 hex digits. Он не используется как routing acceptance. Client-only importer продолжает запрещать FwMark, hooks и management fields.
- J*, padding/timers/CPS/keepalive не принуждаются совпадать. Shared wire fields, PSK/server/header keys, exact client host addresses и other peer overlaps проверяются как раньше.
- Shared safe vocabulary содержит18 field names; полный comparator result с17 конфликтами проходит observation/audit/readiness. Unknown values, duplicate names, null fields или matched-with-conflict metadata отвергаются. Schema6/4/1 не меняется.

## Remaining acceptance

Проверенный go UAPI может не дать explicit selected-peer flag; положительный outcome текущего subset тогда невозможен. Для поддерживаемого core нужно согласовать и проверить core-specific evidence contract; нельзя дописывать synthetic on, брать старый match или checkbox. Binary/core/client matrix, actual negative/positive native run, export/import/connect, DNS/routing/handshake и audited readiness transition открыты в KUK-5. После upgrade сравнения требуется новая actual observation. TTL ledger — diagnostic history, не authorization.

v0.21: immutable AWG runtime target связывает interface/endpoint/tool pin/current boot ID/netns device+inode с profile/exact bytes/revision/TTL. Observe сверяет fixed proc environment на locked OS thread до/между/после readbacks; storage/prepare/fenced recheck требуют independently expected target. Snapshot/JSON не превращаются в native scope. Ledger target не хранит; keyless runtime_target_verified:false и обязательный blocker. Local contracts/proc negative tests не закрывают native/core/client/transition acceptance. ADR-0019, iteration-21; схемы6/4/1 без миграции.
