# ADR-0017 · Частичная сверка Xray users

05.10.2026 · v0.19.0 · KUK-5 In Progress.

## Решение

Добавлен bounded parser expanded TypedMessage JSON GetInboundUsers и read-only native adapter. Fixed root-owned regular /usr/bin/xray, independent lowercase SHA256 pin, execution через pinned file descriptor. Единственная команда — api inbounduser; canonical numeric 127.0.0.1/[::1], explicit inventory tag, timeout3s внутри child4s, output64KiB/users256. Два чтения сравниваются по приватному нормализованному digest: UUID case/JSON whitespace/key ordering/map order не дают ложный drift; изменение users/flow/email/level даёт drift. Нет произвольного executable/config/snapshot под видом runtime, mutations или DNS lookup.

Result immutable, TTL60s, exact bytes и owner/device/profile/generation/revision плюс API server/tag/tool pin. JSON не восстанавливает Result, Summary копирует field names, обычное форматирование не раскрывает private binding/digest. Snapshot constructor всегда configuration-only. Trusted storage после API чтений повторяет current pending binding, key/AEAD/format/credential uniqueness/exact bytes/TTL в read transaction. Клиентские bytes и API response очищаются caller/adapter; raw UUID/email/URI/ошибки не попадают в DTO/ledger/audit.

CLI profile-observe-xray-users всегда read-only, не принимает apply/ready/input/tool. Даже совпадение даёт status:blocked/exit1. Никакого ready/state/audit/installed_revision перехода; keyless readiness CLI и HTTP не получают ключ или новые routes.

## Обнаруженные границы upstream

Pinned source: XTLS/Xray-core 7da5dae6502b787fc6d903863e9a6c5043d107a2. VLESS ProcessUUID обнуляет байты6/7; GetAll перечисляет email map и пропускает unnamed users. Поэтому отсутствие — credential_unobserved, а не доказательство удаления. EnumerationComplete всегда false. Local loopback insecure API и pin CLI не удостоверяют responding core/version/config revision; CoreIdentityVerified/RevisionVerified/TransportVerified/ClientsVerified/Ready всегда false. REALITY key/SNI/shortId/endpoint/routing/handshake не проверяются users API.

SameCredential консервативно резервирует все UUID aliases по данным этого Xray contract, сохраняя исходный UUID и exact export bytes. Snapshot/readback отвергают duplicate wire identities; alias не становится exact UUID match. Правило ограничивает поддерживаемый importer subset; оно не заявляет одинаковую семантику всех VLESS implementations. Старые encrypted rows проверяются заново при импорте/observer load/recheck, миграции нет.

## Приёмка

Synthetic parser/injected-reader tests и encrypted DB/CLI guards — локальная проверка контракта. Native positive binary/API/core/client execution не выполнялась. Для полного KUK-5 нужны pinned responding core/provenance, independent current revision, transport evidence, actual client round-trip и audited transition; четыре acceptance пункта остаются unchecked. Нельзя трактовать partial result или отсутствие пользователя как readiness/revoke confirmation. Source pins: xray-users-contract.md. Схемы6/4/1; VPS/network config/deploy не затрагивались.
