# ADR-0003 — автоматическая передача настроек RU ↔ Foreign

Статус: принято направление; сетевой протокол и криптографическая реализация НЕ готовы.

## Цель

Один раз привязать узлы, затем автоматически получать все необходимые RU параметры межсерверных подключений. Общий versioned descriptor и protocol adapters используются и при ручном импорте, и при автоматическом обмене. Панель родственников не участвует в обмене секретами.

## Границы доверия и последовательность

1. Каждый узел создаёт собственный identity key в agent secret store. Не использовать общий пароль, копию root SSH key или самодельное шифрование.
2. Администратор передаёт RU одноразовое приглашение, endpoint и независимо проверенный anchor/fingerprint Foreign. Token короткоживущий, одноразовый, с достаточной энтропией; claim привязан к RU public key. Подлинность узла проверяется ДО передачи token.
3. Серверы устанавливают mTLS-соединение с проверкой цепочки/идентичности, срока и revocation state. Способ CA provisioning, выпуск/ротация сертификатов и trust-anchor recovery уточняются GW-01/02; запрещены InsecureSkipVerify и silent trust-on-first-contact.
4. RU из host namespace по обычному RU uplink запрашивает capabilities и новую ревизию своего descriptor. Управляющее API независимо от пользовательского hop.
5. Foreign создаёт для конкретного RU новые credentials. Серверный REALITY private key остается на Foreign. Сообщение содержит schema_version, sender/recipient IDs, trust_epoch, revision, predecessor и времена.
6. RU проверяет схему, размер, peer scope, monotonic revision, совместимость adapters, allowlisted endpoint policy. Foreign не может прислать shell, файловый путь, firewall policy, произвольный sing-box JSON или DIRECT.
7. Новая конфигурация staging → syntax/semantic validation → проверка через отдельный outbound → переключение → ACK с applied revision/hash. Только после подтверждения и grace period удаляется старый доступ.

## Повтор, ротация и восстановление

Idempotency на обеих сторонах; повтор ACK безопасен. Потеря управляющего API не стирает last-known-good конфигурацию. Неизвестный результат операции приводит к reconcile. При компрометации credentials разрешён emergency revoke без grace period, даже если это прерывает подключение.

Низшая revision не принимается как «обновление». Откат — новая повышенная ревизия на основе допустимой старой конфигурации, с учетом revocation journal. Смена trust anchor не может подтверждаться только новым неизвестным ключом: нужна действующая доверенная цепочка или явное административное восстановление.

mTLS обеспечивает канал. Для файла ручного переноса нужна аутентичность вне канала: в GW-03 выбрать стандартный подписанный envelope и проверенную библиотеку, связать signature с sender/recipient/schema/revision. Нельзя считать json hash подписью. Шифрование экспортного файла/secret delivery проектируется отдельно; metadata schema сама не защищает секреты.

Новый сервис Foreign-control не совмещается неявно с публичным probe: разные auth policies/virtual hosts, без раскрытия node credentials браузерному endpoint. Общий Foreign IP остаётся общей точкой отказа.

## Реализовано сейчас

Только control DB metadata tables, draft envelope schema, этот ADR и GW backlog. Нет pairing token endpoint, CA/mTLS server, pull loop, transport secrets или автоматического изменения sing-box. Не использовать draft schema для передачи реальных credentials.
