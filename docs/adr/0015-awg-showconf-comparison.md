# ADR-0015 · AWG readback comparison correctness

Статус: принят для локального M1 subset · 05.10.2026 · KUK-5.

## Причина

v0.15/16 мог возвращать peer_matches для selected AdvancedSecurity=off/missing; comparison пропускал server-on/client-omitted boolean conflict. Parser отвергал hex FwMark upstream showconf. Safe metadata reader ограничивал mismatch list16 именами при расширении comparator. Нужны регрессии, которые проходят весь storage/report путь.

## Решение

Require explicit on у выбранного peer; off/unknown становится advanced_security conflict. Unknown peers не меняются. Normalize omitted booleans=off симметрично; new bounded hex FwMark только readback, не importer/network. Централизовать closed vocabulary18 полей; accept full safe conflict без обрезки, reject arbitrary/duplicate/null names. Схемы и commands без изменений.

Source inspection закреплён commit/hash в awg-showconf-contract.md. В inspected AWG go UAPI нет selected-peer flag: этот core ещё не поддержан positive observer contract. Нельзя silently default missing=on. Source research/regression tests не закрывают native execution или клиентскую compatibility.

## Границы

Нет readiness transition/download/client proof, network mutator или новых CLI flags. profiles pending, installed_revision не меняется. Старые ledger rows не превращаются в permission; actual observation должна быть получена заново после upgrade. Runtime/client manifest и standalone audited transition остаются KUK-5 blockers; G1 открыт.
