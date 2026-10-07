# Локальный SQLite стенд

## Запуск

`npm run setup`, `npm run build`, `npm run demo`. Runner выполняет `vpnctl demo-init`, который создаёт `var/demo/portal/state.db` и `var/demo/control/state.db`. Повтор не перезаписывает fixtures и timestamps. HTTP процессы открывают только portal DB read-only; control существует для следующего этапа, без сетевых действий.

## Показать сохранение изменений

При запущенном или остановленном demo:

```sh
./build/vpnctl db-status
./build/vpnctl demo-rename --id dev-iphone --name "Мой сохранённый телефон" --expected-revision 1
```

На Windows executable называется `vpnctl.exe`. Обновить страницу; затем остановить/перезапустить demo: имя остаётся. При следующем переименовании передать ожидаемую ревизию 2, затем 3 и т.д. Устаревшая ревизия отклоняется. Эта CLI-команда доступна только для demo-marked DB и фиксированного demo-family; это не production endpoint выдачи/отзыва VPN.

## Миграции

Только явный local CLI выполняет миграции. HTTP startup с missing/old/future/wrong-kind/bad-checksum DB завершается с ошибкой. Для применения известных миграций к демо остановить HTTP процессы и повторить demo-init. Не править уже применённые migration SQL: добавлять следующий файл. Если проверка не прошла — сохранить файлы и выяснить причину, не затирать history и не понижать user_version вручную.

Это ещё не backup/restore CLI. Копирование одного .db при активном WAL не является корректным backup. Не использовать эту БД для реальных секретов. Reset при необходимости выполнять через новый `--root` и соответствующий `--portal-db`, сохранив прежний каталог; автоматического удаления пользовательских данных нет.

## Permissions

Linux: приватные каталоги 0700, файлы 0600. Control должен принадлежать отдельному control UID при production deployment. Сейчас всё запускается владельцем рабочего каталога; ОС-изоляция двух UID в demo не заявляется. Windows требует будущей явной ACL настройки.
