# Состояние протоколов в кабинетах · v0.27.0

На каждой карточке AWG/REALITY в пользовательском ЛК и authenticated admin device view показаны подключение, конфигурация и раскрываемые проверки подключения. Цвет сопровождается текстом; на мобильном экране блок переносится. «Обновить список» читает сохранённые данные, не выполняет сетевой probe.

| Индикатор | Что он означает |
|---|---|
| Подключение: нет данных | Свежий session/traffic proof в HTTP не поступает. Это не offline и не подтверждение отзыва |
| Проверка не выполнена | Нет импортированного профиля или пригодного результата |
| Сохранена, ждёт сверки | Encrypted profile сохранён; применённый доступ не подтверждён |
| Совпадает по сверке | Только сравнение конфигурации в пределах TTL; источник показан отдельно |
| Обнаружено расхождение | Последняя пригодная configuration metadata содержит конфликт |
| Результат устарел | TTL60s истёк; новые данные нужны независимо от прежнего совпадения |
| Нужна новая сверка | Generation/revision/current state изменились либо timestamp в будущем |

Источники: «сохранённая копия» — snapshot comparison; «прочитанные настройки» — metadata доверенного AWG native readback. Ни один источник не подтверждает сейчас responding core, маршрут, DNS, проверенный клиент или ready. Для REALITY existing partial named-users observer не записывает такую configuration ledger: после импорта остаётся «Сохранена, ждёт сверки». Руководство/каталог приложений не меняет индикаторы проверки.

Сервер выдаёт только закрытые display enums и checkedAt/expiresAt. Owner/current profile/generation/revision, user/device/profile state, canonical timestamps/TTL и allowed source/metadata проверяются в одном read snapshot. Последний конфликт/expired/stale/future/corrupt result не скрывается старым совпадением; fractional seconds учитываются. Raw mismatched fields, observation IDs, config/URI/UUID/ключи/hashes не передаются. SQLite schema остаётся6/4/1.

`GET /api/v1/devices` ограничен owner session. Admin получает ту же projection только через отдельный authenticated management listener и read-only portal DB; pages≤100. Никакого control DB, socket, key file или `/usr/bin/awg`/Xray доступа HTTP не получает. Это отдельный display read model, не trusted CLI `profile-readiness` DTO и не permission/transition. Native AWG session result остаётся immutable read-only CLI-only; ledger/audit не расширены.

В браузере срок совпадения проверяется ежесекундно. Будущие/некорректные timestamps не становятся зелёными при ожидании. Нет кнопок manual ready, client checkbox или автоматической выдачи по индикатору. VPN-клиент, передача данных и DNS/маршрут помечены непроверенными, пока отсутствует independently bound actual proof и отдельная audited readiness transition.

Проверки projection используют synthetic portal rows для owner/current/latest/TTL/privacy/read-only boundaries. Browser tests с mock API проверяют визуальное отображение и expiration на desktop/mobile; они не доказывают VPN, native session collector или production admin isolation. Фактические execution/acceptance ограничения — `iteration-27.md`.
