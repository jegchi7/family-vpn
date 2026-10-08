# Итерация 27 · v0.27.0 · 08.10.2026

## Согласование ядер, диагностика в кабинетах и GitHub bootstrap

По запросу владельца продолжена подготовка платформы к закреплённым VPN-ядрам и добавлено отображение проверок протоколов в пользовательском кабинете и защищённой админке. Настоящее соединение пока не наблюдается через HTTP: интерфейс честно показывает «Нет данных», проверки клиента/передачи/DNS/маршрута не подтверждены. Кабинет и установленные bytes не считаются рабочим VPN. К VPS задача не подключалась; firewall/routes/SSH/services и публичный deploy не менялись.

Версии Xray 26.3.27, sing-box 1.14.2 и Hysteria 2.13.0 вынесены в общие константы установщика и Foreign generator. Закреплённые Linux assets/hashes сохранены. `core-plan/install/status` показывают закрытую compatibility matrix: Foreign primary template, RU outbound fragment, partial named-users observation или отсутствие конфигурации backup. Configuration scope не является running-core/client acceptance; native/client/ready false. URI/AWG import subset не расширен, AdvancedSecurity и независимые scope/inventory guards не ослаблены.

`ProfileDiagnostics` — отдельная безопасная проекция существующих portal metadata, а не trusted CLI readiness DTO. Пользователь получает только свои current-generation profiles; админ — те же классификации в authenticated management read-only pages ≤100. Нет profile key/control DB/agent socket/tool или network calls. Source ограничен none/snapshot/native_readback; raw observation IDs, mismatch names/values, hashes, keys и runtime target не выдаются. Историческая запись native source не удостоверяет текущий target/core/revision.

Для сохранённого AWG профиля показываются stored/matched/conflict/expired/stale с owner/device/profile/generation/revision/state binding и TTL 60s. Последняя конфликтующая, устаревшая или будущая запись не скрывается старым совпадением. Все чтения устройства/профилей/диагностики используют один DB snapshot; rename response сразу инвалидирует прежнюю revision. Invalid temporal history подавляет положительный badge: SQL проверяет canonical UTC spelling, календарную дату и дробную часть обоих timestamps до выбора записи. Это исправляет расхождение SQLite normalization с Go parser. UI дополнительно снимает положительный результат при локальном expiry без reload. Configuration match не меняет ready/installed_revision/download/cancel permissions. Для REALITY нет выдуманного результата по отсутствующему stored observer.

Подготовлен GitHub delivery pipeline для official `jegchi7/family-vpn` main. Публикация допускается только после полного checks job; PR/fork не получает публикацию. Publisher повторно связывает main/tag/release с точным source commit, сначала создаёт draft, загружает закрытый набор четырёх assets (amd64/arm64 tar.gz и sidecars), затем публикует prerelease. Совпавший комплект идемпотентен; существующие assets/tag не заменяются, конфликт требует новой версии. Это доставка operator bundle, не публикация приложения/VPN.

`scripts/bootstrap-github.py` совместим с Python 3.8 и использует fixed public repo/version/URLs без environment proxy. Перед apply проверяются independently fetched main commit, tag/release target и четыре asset names/digests; архив и sidecar сверяются, closed tar extraction потоковая, bounded и без links/traversal, manifest/files/ELF/permissions проверяются. Whole-download deadline включает root Linux alarm, чтобы непрерывная медленная передача не обходила timeout. Apply Linux root-only, SDK на VPS не нужен; role RU/Foreign выполняет существующую ограниченную установку/staging, не активирует сеть. Скрипт и workflow этой версии удалённо не запускались; release/push/publication не выполнены.

Независимые reviews привели к двум существенным исправлениям: whole-download deadline и повреждённые timestamps перед старым положительным сравнением. Дополнительных actionable findings после исправлений не обнаружено. Это локальный review, не эксплуатационная приёмка.

## Проверки на текущем Windows компьютере

Node 24.21.0/npm 11.19.0, pinned Go 1.27.1, installed Chrome через `FVPN_TEST_BROWSER=chrome`. SDK/cache/parser tools/private state остаются вне source/runtime packages.

- `npm run build` PASS: Svelte 0 errors/0 warnings, Vite 122 modules, шесть Go executables. API generation drift PASS.
- Изменённые Go packages/CLI и Go vet PASS. Core packages дополнительно проходят Linux amd64/arm64 CGO0 cross-vet и test-binary compile; это не Linux execution.
- Опциональный SHA-pinned Windows Xray/sing-box parser regression PASS: generated IPv4/IPv6 pairs принимаются, malformed REALITY keys отклоняются; восемь parser invocations. Временные конфиги удалены, вывод suppressed, listeners/services не запускались. Ни Ubuntu execution, ни REALITY transport/client round-trip этим не подтверждены.
- Diagnostics backend PASS: latest fractional/conflict/future/TTL/revision/generation, malformed timestamp ordering, owner isolation, user/admin projection, read-only/no audit/state mutation. HTTP device ownership/admin MFA isolation PASS; migrations не менялись.
- `npm run check` NOT PASS: race/CGO1 требует отсутствующий gcc. Полный check не объявляется успешным.
- Full Go tests CGO0 NOT PASS: прежние Windows strict key/private-file guards остаются причиной failures в cmd/vpnctl, adminauth, clientconfig и profilevault. store/httpapi/core и другие доступные packages PASS; ownership policy не ослаблялась.
- `npm run test:e2e` PASS 16/16: 12 synthetic diagnostic UI cases и четыре demo cases, desktop/mobile. Исправлен initial demo startup race через bounded readiness polling. Mocked диагностические состояния не считаются native observation/client acceptance.
- `npm run test:e2e:auth`: 8 PASS/4 import FAIL на intentional Windows profile-key ownership guard. `npm run test:e2e:admin` BLOCKED при startup на intentional Windows admin master-key guard. Полные Linux auth/admin/import regressions обязательны.
- `npm run test:persistence` PASS. `npm run test:intents` NOT PASS: Windows SIGTERM завершает child с exit null; graceful Linux shutdown не проверен.
- Publisher tests PASS 12/12; release packaging tests PASS 8/8. Bootstrap tests: 10 PASS/1 SKIP — native Linux alarm case не выполняется на Windows. Эти тесты не обращаются к VPS и не публикуют release.
- Bash wrappers `bash -n` PASS. Реальный Linux root operator path и удалённый CI не исполнены.

Source package и Linux amd64/arm64 runtime bundles подготавливаются отдельно после отчёта с allowlisted contents/manifests/checksums. Cross-built ELF не означает execution; state/credentials/TLS keys/core downloads/cache/SDK/control binaries в комплект не входят. Архивы не production/pilot RC и не подтверждают readiness или выдачу рабочих профилей.

## Реестр и открытая приёмка

Canonical snapshot 1.22: исходные 63 work/dependencies/acceptance (252 normative fields) и specification сохранены. Статусы: 44 Backlog/16 In progress/3 Verification/0 Done; GW 8 Backlog, auth extras Deferred. Схемы portal/control/admin 6/4/1, migrations неизменны. Локальная поставка не объявляет обновление Linear, GitHub или remote CI.

M1/G1 и KUK-5/6/7 остаются открыты. Нужны actual Ubuntu root/race/auth/admin/import regression, independently expected core/kernel/client inventory, AWG compatible build и selected AdvancedSecurity contract, kernel guard/vpn-data isolation, RU ingress/selector, backup TLS и настоящий Android→RU→Foreign round-trip с DNS/TCP/UDP/IPv6/Foreign-loss/resource/restart acceptance. Audited writer transition обязан проверить actual client proof и все guards в одной транзакции до ready/download. M2 automation после M1.

Версия поставки: **v0.27.0**.
