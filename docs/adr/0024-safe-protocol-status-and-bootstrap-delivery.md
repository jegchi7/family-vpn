# ADR-0024 · Статусы протоколов и доставка operator bootstrap

Дата: 08.10.2026. Статус: локально реализовано; native/client/network acceptance открыты.

Владелец запросил согласование платформы с VPN cores и визуальные статусы в пользовательском кабинете/админке, а ранее — однострочные команды из вручную обновлённого GitHub. Сборка на VPS Ubuntu20.04/~1GiB не требуется: runtime комплект содержит prebuilt binaries/frontend.

Версии Xray/sing-box/Hysteria берутся из общего closed pinned catalogue. Compatibility matrix описывает поддержанный configuration/observation scope и ограничения, отдельно от integrity/install, responding runtime и client proof. Import subsets не расширены. AWG AdvancedSecurity/native source guards сохранены.

HTTP показывает отдельную safe display projection существующей configuration metadata. Это не копия trusted readiness report: enum summary и timestamp без raw fields/IDs/values, keys, control, tool/network вызовов. Read transaction связывает owner/current generation/revision, latest observation и TTL; latest negative/corrupt metadata запрещает fallback к старому match. Connection unknown/client unchecked сохраняются. Реальный session collector и actual proof transition будут отдельным этапом M1/G1.

CI после всех checks/E2E строит amd64/arm64 комплекты и для main push официального repository готовит matching draft release, загружает четыре assets с digest проверками, затем publishes prerelease. Checked current main SHA и tag проверяются; существующие assets не заменяются/удаляются, конфликт требует новой package version. При прерывании matching draft можно продолжить. Это artifact distribution, не application/network deployment. Локальная задача ничего на remote не публикует.

Root bootstrap Python3.8-compatible загружается с independently pinned script SHA. Default dry-run без download/write; apply только Linux root. Фиксированные public GitHub sources, no env proxy, bounded HTTPS/redirect/time/size, independent main/tag/package/release/digest binding, streamed safe tar/manifest/checksum/ELF checks предшествуют любому executable. Новый private root directory сохраняет старые комплекты. RU устанавливает xray/sing-box; Foreign создаёт либо проверяет existing staging. Service/firewall/routes/SSH/ready не меняются; повтор partial preparation не удаляет установленное ядро или credentials.

Реальный Ubuntu root/race/auth/admin/import/namespace/kernel/Android execution остаётся обязательным; Windows config-only core checks и synthetic UI/metadata tests этого не заменяют. Нормативные63 criteria/status counts и deferred auth extras не изменены.
