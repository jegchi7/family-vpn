# Дополнение backlog: GW — обмен настройками шлюза

Все задачи пока Backlog. Дополняет исходные 63 задачи; общий список теперь **71 задача**. GW — отдельная дополнительная поставка после базовых агентов. Статус «ADR принято» не означает готовый протокол.

| ID | Задача | Зависимости | Проверяемый результат |
|---|---|---|---|
| GW-01 | Утвердить threat model, identities, CA/cert lifecycle и schemas | PRE-03/05/06, DEV-03 | Bootstrap без TOFU, секреты отделены от metadata, правила expiry/replay/rollback и TLS virtual hosts оформлены |
| GW-02 | Реализовать enrollment и взаимную аутентификацию | GW-01, DEV-14 | Одноразовый token привязан к RU key, повтор/чужой peer/неверный сертификат/истёкший token отклоняются; token не уходит неизвестному серверу |
| GW-03 | Реализовать общий descriptor и безопасный offline import/export | GW-01, PRE-04, DEV-07 | Те же schema/validation используются при import и pull; стандартная signature/encryption проверена; private Foreign key и DIRECT исключены |
| GW-04 | Реализовать Foreign control service и protocol adapters | GW-02/03, NET-05 | Credentials ограничены одним RU; подготовка повторяема; public probe не имеет доступа к control methods |
| GW-05 | Реализовать RU pull, capabilities и cache | GW-04, DEV-14/15, NET-02 | Получает только свою ревизию, reject rollback/unsupported schema; отказ control API не ломает last-known-good hop |
| GW-06 | Реализовать prepare/test/commit/ACK и согласованную ротацию | GW-05, DEV-18/21 | Обрыв на каждом шаге восстанавливается, старый доступ удаляется после подтверждения, emergency revoke не возвращается откатом |
| GW-07 | Добавить закрытый экран «Шлюз» | GW-06, DEV-12/22 | Привязка, desired/observed revision, ошибки, verify/apply, понятные incomplete states; секреты не раскрываются в public UI |
| GW-08 | Провести security/fault-injection приёмку и пилот | GW-07, QA-02/04/10, ROL-01 | MITM/replay/expired cert/token reuse/capability mismatch/reboot/restore/cross-node scope проверены; нет direct egress |

Размеры до GW-01: GW-01 M, GW-02 L, GW-03 L, GW-04 L, GW-05 M, GW-06 L, GW-07 M, GW-08 L. Это оценки объёма, не календарные обещания. Внутри L задачи разбить после утверждения контрактов.

В v0.2.0 подготовлены задел для GW-01/03 и metadata schema. Ни одна GW-задача полностью не закрыта.
