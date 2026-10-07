# ADR-0009 · Ограниченный trusted client importer

Дата: 04.10.2026. Статус: принято для локального семейного MVP.

DEV-08 начинается с одного документированного формата — VLESS/REALITY TCP/Vision URI. Основание и scope закреплены в client-format-matrix.md. AWG 3.1 и Amnezia wrappers требуют самостоятельной проверки новых полей и client-only schema; importer не применяет serializer прежнего AWG.

Выбрана строгая allowlist полей/значений; входные bytes сохраняются целиком без URI reserialization. Credentials принимаются через bounded private file/stdin, не argv. Parser ошибки и CLI отчёты используют фиксированные коды без input/UUID/pbk. Format validation не устанавливает actual peer и не доказывает client handshake.

CLI `profile-targets` выдаёт nonsecret binding metadata. `profile-import` по умолчанию открывает БД read-only; `--apply` повторяет проверки под writer lock. Проверяются owner/device/profile/current generation/pending state/revision и active encryption key. Повтор exact bytes возвращает existing record; другое содержимое конфликтует. Parser вызывается повторно на storage boundary, поэтому direct call ImportClientProfile также защищён.

Один UUID резервируется одному неотозванному profile независимо от owner/endpoint — сознательная консервативная политика небольшого сервиса. Проверка сканирует известные импортированные records, расшифровывает/валидирует их в памяти и сравнивает UUID без постоянного credential digest. Включает disabled owners и незавершённый revoke. SQLite writer lock сериализует конкурирующие imports; key rotation не теряет связь, поскольку check использует decrypted exports.

Apply записывает encrypted pending bytes и audit одной транзакцией. Сохранение не создаёт installed revision/IP allocation, не вызывает agent и не публикует доступ. UI показывает сохранённый ожидающий профиль и убирает кнопку отмены; server guard остаётся обязательным. Unknown peers не удаляются: runtime network adapter отсутствует.

DEV-08 остаётся In progress: actual RU peer reconciliation, AWG preservation и real client round-trip ещё открыты. DEV-09 verified download/QR идёт после них. Дополнительные auth mechanisms не возвращаются в приоритет этой итерации.
