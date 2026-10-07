# ADR-0012 · AWG3.1 client import и фокус M1

Дата: 05.10.2026. Статус: принято для локального семейного MVP.

Владелец выбрал следующий milestone M1/G1. Сохраняем задел DEV-14/15, но последовательность следующих поставок ведёт через ручную выдачу профилей. Декомпозиция и доказательства — milestone-m1.md; исходные критерии и ID основного backlog не сокращаются.

Добавляем явный формат awg-3.1-conf к trusted importer. Принимаем один клиентский Interface/Peer и перечисленные поля 3.1, включая header protection, content padding, timings, trailers/cookies и CPS. Ограничения указаны в client-format-matrix.md. Allowlist закрыта: не принимаем wrappers/management/hook directives/unknown extensions. Оператор отвечает за происхождение файла: синтаксис не доказывает, что это экспорт с действующего устройства, и не является DLP-анализом комментариев.

Не используем INI serializer: encryption хранит исходные bytes целиком, поэтому никакой новый параметр, комментарий или порядок строк не теряется. Validator не запускает awg-quick, core, subprocess, DNS или сеть. CLI выбирает protocol по известному format, storage повторно проверяет совпадение с выбранным pending slot.

Credential identity — derived X25519 public key. Сравнение raw PrivateKey позволило бы пропустить два ключа, отличающихся clamped bits, поэтому оно не применяется. Identity остаётся private in-memory field Validated, без нового DB digest/DTO. Конкурирующие imports сериализуются existing writer transaction; key rotation сохраняет conflict checks. VLESS UUID занимает первые16 bytes expanded32-byte identity; Xray preflight продолжает сравнивать ровно UUID16. Новых migrations нет.

AWG3.1 .conf importer готов локально, native app/core compatibility пока не подтверждена. Apply сохраняет pending и не создаёт installed_revision. Дальше — independent runtime evidence + pinned client round-trip, затем owner download/QR. Snapshot/fake/успех CLI import не заменяют эти доказательства.
