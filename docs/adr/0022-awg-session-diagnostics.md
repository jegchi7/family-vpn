# ADR-0022: отдельное AWG session observation

Дата:07.10.2026. Статус: принято для локальной реализации v0.25; native acceptance открыта.

## Контекст

Владелец подтвердил работу кабинета на RU. Для VPN есть два пока неподготовленных сервера Ubuntu20.04/~1GiB; первый тестовый клиент Android. Нужна измеряемая selected-peer диагностика соединения до выдачи. Configuration `showconf` не сообщает факт клиентского импорта, successful routing или активный data path. Existing AWG comparator требует independently proven selected-peer AdvancedSecurity; этот guard не ослабляется по handshake.

## Решение

Добавить `profile-observe-awg-session` и отдельный immutable `SessionResult`, который не совместим с configuration `Result`. Fixed pinned tool читает только named-interface latest-handshakes/transfer в current independently expected boot/netns, с двухсекундным интервалом. Parser bounded/closed, identity derived from validated frozen exact client bytes. Сводка не содержит peer keys/counters/targets. JSON не становится native evidence; lifetime не больше60s.

Повторная read transaction проверяет current DB binding/key/envelope/format/uniqueness и opaque result. Нет writer mutation, observation ledger/audit, HTTP views или profile-ready transition. Всегда blocked/exit1 и явные false core/revision/client/DNS-routing/ready flags. Ни CLI inputs, ни snapshot, ни checkbox не заменяют attestor.

## Последствия

Оператор может увидеть свежесть handshake и движение selected-peer counters после подготовки реального стенда. Эти результаты не удостоверяют expected endpoint/загруженную конфигурацию, Android import/build или путь RU→Foreign; изменения runtime и reset counters трактуются консервативно. Нужны отдельные core/revision/client evidence и одна audited writer transaction перед delivery. User HTTP не получает key, tool/network namespace capabilities или control DB. M1/G1 и полные original63 criteria остаются открыты.
