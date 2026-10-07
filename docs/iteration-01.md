# Итерация 01 — фактический результат

Дата: 2026-09-29. Поставка: `family-vpn-starter-v0.1.0.zip`. Это локальный исходный проект, не production release.

## Реализовано

- Go-модуль, команды сборки/check/demo, Svelte + TypeScript, зафиксированные npm dependencies и lockfile.
- Два отдельных read-only HTTP listener: portal :8080 и admin :8081. Numeric loopback и явный --demo обязательны.
- Устройства текущего фиктивного пользователя, отказ доступа к чужому fixture, готовый/ожидающий профиль.
- Скачивание текстовой demo-памятки (не VPN-конфига), инструкции по платформам и безопасно обозначенные тестовые статусы.
- Freshness в API и браузере: через 60 с статус unknown, timestamp не обновляется простым GET.
- OpenAPI 3.1 JSON реализованного subset и сгенерированные TypeScript DTO; проверка их синхронности.
- Production режим portal/admin и будущие node-agent/hop-controller/foreign-probe завершаются с ошибкой.
- CI workflow без auto-deploy, исходные требования/backlog, inventory template, ADR локального bootstrap и план продолжения.

## Фактические проверки

| Проверка | Результат |
|---|---|
| Go 1.27.1: go vet ./... | PASS |
| Go: go test -race ./... | PASS: 4 test functions, включая 9 boundary subcases |
| Svelte/TypeScript | 0 ошибок, 0 предупреждений |
| API generation drift | PASS |
| Vite build | PASS; JS gzip 18.19 kB, CSS gzip 1.99 kB, HTML gzip 0.30 kB |
| Сборка всех 5 Go executables | PASS |
| Запуск portal без --demo | Заблокирован, exit 1 |
| Запуск demo на 0.0.0.0 | Заблокирован, exit 1 |
| node-agent/hop-controller/foreign-probe | Завершаются exit 2, ничего не меняют |
| Browser E2E | 4/4 PASS: 2 сценария × desktop 1365×900 / mobile 320×800 |
| Визуальная проверка | Desktop и mobile скриншоты просмотрены; основное содержимое не обрезано |

Среда проверки: Linux x86_64, Go 1.27.1, Node 24.19.0, npm 11.9.0, Svelte 5.57.1, Vite 8.3.1, svelte-check 4.7.6, TypeScript 5.9.3, Playwright 1.63.0.

Обычная установка Playwright Chromium в этой среде вернула повреждённый архив. E2E выполнены с альтернативно полученным Chromium 153.0.8010.0 и внешней local launch-конфигурацией; browser web security не отключалась в успешном прогоне. Первоначальный запуск с single-process завершал браузер между тестами; после удаления этого флага все 4 теста прошли. Эти runtime-зависимости и специальная локальная конфигурация не включены в исходный проект; на обычном компьютере/CI используется стандартный Playwright install. Полный GitHub Actions run ещё не выполнялся. Windows/macOS запуск и реальные мобильные VPN-клиенты не проверялись.

Скриншоты находятся в `screenshots/`. Они содержат только demo fixtures.

## Состояние backlog

| Задачи | Статус этой поставки |
|---|---|
| DEV-01 | Каркас и локальная сборка реализованы; CI workflow подготовлен, удалённый run ожидается после загрузки в Git |
| DEV-03 | Частично: контракт demo subset. Полный production auth/mutation/agent контракт впереди |
| DEV-06/09/10/11/12/13 | Только prototype seams: фиктивные устройства, download note, черновые инструкции, read-only UI, freshness |
| DEV-02, DEV-04/05/07/08, DEV-14…26 | Не реализованы |
| PRE/NET/ROL | Не выполнялись на настоящих узлах; inventory остаётся UNKNOWN |
| QA | Локальные regression/e2e tests не заменяют нормативную AT приёмку production системы |

G0/G1 и последующие gates не пройдены. Fixed demo identity не является аутентификацией, ownership fixtures не доказывает защиту multi-user production, status fixtures не измеряют сеть.

## Следующий шаг

См. `next-iteration.md`: реальные store interfaces/SQLite и auth contract, затем защищённый вертикальный сценарий invitation → session → own devices. Пока сохранять блокировку production запуска. Перед real agent и network policy нужно выполнить обследование и построить отдельный сетевой стенд.
