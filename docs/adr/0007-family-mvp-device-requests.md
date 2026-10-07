# ADR-0007 — приоритет семейного MVP и локальные заявки

Решение владельца 30.09.2026: сервис для своих, дополнительное усложнение авторизации не является приоритетом. Реализованные user passwords/invites/recovery и admin TOTP сохраняются. WebAuthn, recovery codes и fresh auth откладываются за текущий MVP; это изменение очереди, не заявление о выполнении прежней полной DEV-05. Базовые session/CSRF/ownership остаются, неизвестный URL панели не заменяет контроль доступа. Текущих опасных admin HTTP mutations нет.

Чтобы продвинуть основной сценарий, v0.6 вводит device request: name/OS/owner, квота и два pending profile slots. Проверенные app versions, ключи, адреса и installed revision пока отсутствуют. HTTP записывает намерение; не вызывает агент/CLI/network. Поэтому API отвечает 200 с состоянием pending и UI не обещает рабочий доступ. Request replay возвращает текущее состояние объекта, а не старый snapshot: rename/cancel не откатываются.

Portal migration v4 хранит creation_key и hash нормализованного payload, unique(owner,key). Квота и write сериализуются SQLite writer lock, поэтому last-slot race имеет одного победителя; повтор той же заявки возвращает тот же ID. Revision обязателен для rename/cancel. Audit пишется в той же транзакции. Общая история ограничена 200 записями на пользователя; активная квота по умолчанию 5.

Cancel не заменяет revoke: допускается лишь для созданной request flow pending-записи без любого подготовленного/secret-bearing/installed поколения и без subscription. Это локальная отмена невыданной заявки; в БД device/profile states становятся revoked, слот освобождается, key idempotency остаётся. Состояние active/partial или legacy device не может попасть под такую отмену. Сетевой отзыв с прекращением существующих сессий реализуется отдельно.

Основной backlog теперь живой: карточки и статусы актуализируются в vpn-platform-backlog-v1.0.md, прежние acceptance criteria и ID сохранены. Историческая привязка audit к DEV-22 в ранних отчётах была неточной: DEV-22 — manual override; audit/read-only относятся к DEV-13. Эта поставка исправляет текущий реестр, оставляя историю неизменной.
