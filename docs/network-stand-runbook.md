# RU ingress и изоляция двух серверов

Этот срез добавляет закрытую конфигурацию RU ingress и operator-only инструменты подготовки `vpn-data`. Начальное RU staging содержит **пустой список клиентов**. Подготовка, проверка синтаксиса и kernel readback не разрешают скачивание профиля и не переводят его в `ready`. На VPS из локальной разработки никто не подключался; службы VPN, firewall, routes и SSH здесь не менялись. Native Ubuntu20.04 и Android acceptance остаются открыты.

## Закрытый primary маршрут

```text
Android → RU public IPv4:443 → Xray VLESS/TCP/REALITY
                               ↓ SOCKS 127.0.0.1:1080
                             sing-box → Foreign IPv4:443 → Internet

REALITY camouflage: Xray → 127.0.0.1:10443 → sing-box TCP relay
                                                ↓ тот же Foreign VLESS
                                      выбранный public TLS IPv4:443
```

На RU работают два предполагаемых процесса в одном `vpn-data`: Xray26.3.27 и sing-box1.14.2. Xray слушает `0.0.0.0:443` внутри namespace, default outbound — `blackhole`; единственный разрешённый client route идёт в loopback SOCKS. sing-box принимает SOCKS1080 и отдельный raw TCP relay10443 только на `127.0.0.1`; его единственный outbound — точный полученный private Foreign VLESS fragment. `direct` у relay — **тип входа** с фиксированным override адреса/порта, а не DIRECT outbound или fallback. Произвольные destination, DNS resolver, selector, TUN, hooks и management API в эту схему не входят.

В pinned Xray REALITY camouflage использует отдельный `net.Dialer.DialContext`; `streamSettings.sockopt.dialerProxy` эту ветку не переключает. Поэтому target RU Xray фиксирован как loopback relay, а public TLS target достигается через Foreign. Источники: [Xray REALITY config](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/reality/config.go), [Xray TCP listener](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/tcp/hub.go), [sing-box direct inbound](https://github.com/SagerNet/sing-box/blob/v1.14.2/protocol/direct/inbound.go).

Это IPv4 primary срез: ядра, backup Hysteria/TLS, AWG/TUN и failover требуют отдельных этапов. IPv6 запрещён в kernel plan, включая loopback IPv6; никакого RU DIRECT fallback.

## Приватная подготовка RU

Сначала установить закреплённые ядра по [bootstrap runbook](vpn-bootstrap-runbook.md) и подготовить Foreign private pair. Исходный `/etc/family-vpn/foreign-staging/xray.json` и `ru-hop.json` сохраняются без изменения bytes/credentials. Foreign hop — секретный operator fragment, не пользовательский export и не профиль ЛК.

Перенос exact `ru-hop.json` на RU выполняется отдельно выбранным защищённым operator каналом. Получатель фиксирован: `/etc/family-vpn/ru-import/ru-hop.json`, root-owned файл0600 в root-owned каталоге0700; в каталоге допускается только этот файл. Не передавать fragment через чат, stdout, URL, issue, portal DB или git. Runtime не выбирает произвольный путь и не выполняет remote transfer.

Публичные параметры выбираются оператором независимо: RU IPv4:443, Foreign IPv4:443, отдельный camouflage TLS IPv4:443 и его SNI. Требуются разные публичные literal IPv4; endpoint из fragment должен точно совпасть с независимо введённым Foreign endpoint. Доступность, подходящий TLS и client compatibility этой проверкой не устанавливаются.

Из корня runtime bundle, сначала dry-run с заменой placeholders:

```sh
./build/vpnctl ru-init --endpoint '<RU_IPV4>:443' --foreign-endpoint '<FOREIGN_IPV4>:443' --reality-target '<RU_TLS_TARGET_IPV4>:443' --server-name '<RU_TLS_SNI>'
```

Без `--apply` это только validation несекретных параметров: без чтения hop, генерации ключей и файлов. На разрешённом Linux root стенде `--apply` создаёт **новый** `/etc/family-vpn/ru-staging`0700 с `xray.json`, `sing-box.json`, `ru-hop.json`, `plan.json`0600. Закрытая схема проверяется точным воспроизведением; duplicate/unknown/case-alias JSON, расширение policy и plaintext dump не принимаются. Atomic no-overwrite staging сохраняет уже созданные credentials; при existing stage использовать проверки:

```sh
./build/vpnctl ru-check
./build/vpnctl ru-check --native-check
./build/vpnctl ru-status
```

Все эти чтения требуют Linux root и fixed protected stage. `--native-check` допускает только independently pinned установленные `/usr/bin/xray` и `/usr/bin/sing-box`, descriptor-bound `run -test`/`check`, bounded child lifetime и подавленный private subprocess output. Listener/service не запускается. `native_syntax_validated` относится к parser invocation; runtime, kernel/routing/DNS/client proof и ready этим не устанавливаются.

Initial `clients:[]` намеренно не генерирует UUID неизвестного владельца. Внутренний pure `BindValidatedClient` может получить exact validated VLESS client bytes и сверить endpoint/SNI/derived public key/short ID, сохранив остальные bytes. Он не импортирует профиль, не пишет DB/files, не проверяет owner/generation/revision и не заменяет другую identity. Vault-bound issuance/current profile binding, writer fences и actual client proof остаются отдельной обязательной работой. CLI создания URI/download/manual ready здесь нет.

## Network plan и независимые входы

На обоих серверах используются фиксированные имена `vpn-data`, `fvpn-host`, `fvpn-ns`. Оператор выбирает не пересекающийся с текущими addresses/routes RFC1918 `/30`: `.1` на host veth, `.2` внутри namespace. Нужны выбранный uplink, public IPv4 на нём и ровно один соответствующий IPv4 default route. Role `ru` требует host IPv4 равный RU; `foreign` — Foreign. Существующие namespace/veth/tables, конфликтующие пути или некорректный inventory запрещают автоматическое продолжение.

Network apply/check требует независимо ожидаемый **текущий host boot ID, host netns device+inode и SHA256** root-owned package helpers: fixed `/usr/sbin/ip`, `/usr/sbin/nft`, `/usr/sbin/sysctl`, `/usr/sbin/tc`. Разрешён только закрытый Ubuntu layout alias `ip` к защищённому package binary. Текущий proc/inventory read не заполняет отсутствующие ожидания и не подтверждает доверие незнакомому хосту. Нет arbitrary tool/path/snapshot flags, PATH lookup или сохранённого JSON proof. Namespace override канал `/etc/netns/vpn-data` запрещён.

Namespace helper запускается через held namespace descriptor: отдельный locked OS thread входит в него через `setns`, проверяет target, запускает fixed protected helper и восстанавливает expected host scope. Если restoration не подтверждено, child group прекращается, а thread не возвращается в Go pool. Единственный host veth move передаёт тот же descriptor в закрытом `/proc/self/fd/4` аргументе; повторного выбора namespace по имени нет. Upstream support: [iplink NET_NS_FD](https://github.com/iproute2/iproute2/blob/v5.5.0/ip/iplink.c#L634-L646), [FD path reader](https://github.com/iproute2/iproute2/blob/v5.5.0/lib/namespace.c#L96-L109). Реальный Linux запуск этой границы ещё не выполнен.

Команды имеют разные эффекты:

| Команда | Область |
|---|---|
| `network-plan` | Validation явных public topology inputs, без native вызовов/записи |
| `network-prepare` без `--apply` | Тот же dry-run |
| `network-prepare --apply` | Fresh protected inventory/tool/scope checks; новый private `network-staging`, без network mutation |
| `network-check` | Read-only protected artifact validation |
| `network-check --native-check` | Fresh topology/kernel readback с independent expected scope/pins; не profile readiness |
| `network-apply` без `--apply` | Dry-run |
| `network-apply --apply` | Только закрытая operator network процедура после всех guard/recovery условий; VPN cores не активирует |

`network-staging` содержит canonical manifest и exact generated host/namespace nft plans. Для Foreign туда дополнительно попадает новый private `foreign-xray.json`: adapter сначала проверяет original pair, затем меняет **только** DNS `UseIPv4` и freedom `ForceIPv4`. Credentials, peer, source и deny rules сохранены; IPv6 endpoint/source/camouflage rejected. Original pair остаётся отдельно и никогда не autoupgrade/rewrite.

Примеры с placeholders относятся к operator CLI из matching runtime bundle. Сначала dry-run topology на RU и Foreign; `<TRANSIT_CIDR>` включает `/30` и выбирается отдельно на каждом хосте:

```sh
./build/vpnctl network-plan --role ru --ru-ipv4 '<RU_IPV4>' --foreign-ipv4 '<FOREIGN_IPV4>' --host-ipv4 '<RU_IPV4>' --transit '<TRANSIT_CIDR>' --uplink '<RU_UPLINK>'
./build/vpnctl network-plan --role foreign --ru-ipv4 '<RU_IPV4>' --foreign-ipv4 '<FOREIGN_IPV4>' --host-ipv4 '<FOREIGN_IPV4>' --transit '<TRANSIT_CIDR>' --uplink '<FOREIGN_UPLINK>'
```

После independent host/tool inspection можно подготовить private artifacts. Здесь `--apply` относится **только к staging**; ни ссылки, ни firewall, ни forwarding не меняются. Ожидания boot/netns/hashes берутся из independently accepted текущего хоста, а не автоподставляются самим инструментом:

```sh
./build/vpnctl network-prepare --role ru --ru-ipv4 '<RU_IPV4>' --foreign-ipv4 '<FOREIGN_IPV4>' --host-ipv4 '<RU_IPV4>' --transit '<TRANSIT_CIDR>' --uplink '<RU_UPLINK>' \
  --boot-id '<EXPECTED_BOOT_ID>' --netns-device '<EXPECTED_HOST_NETNS_DEVICE>' --netns-inode '<EXPECTED_HOST_NETNS_INODE>' \
  --ip-sha256 '<EXPECTED_IP_SHA256>' --nft-sha256 '<EXPECTED_NFT_SHA256>' --sysctl-sha256 '<EXPECTED_SYSCTL_SHA256>' --tc-sha256 '<EXPECTED_TC_SHA256>' --apply
./build/vpnctl network-prepare --role foreign --ru-ipv4 '<RU_IPV4>' --foreign-ipv4 '<FOREIGN_IPV4>' --host-ipv4 '<FOREIGN_IPV4>' --transit '<TRANSIT_CIDR>' --uplink '<FOREIGN_UPLINK>' \
  --boot-id '<EXPECTED_BOOT_ID>' --netns-device '<EXPECTED_HOST_NETNS_DEVICE>' --netns-inode '<EXPECTED_HOST_NETNS_INODE>' \
  --ip-sha256 '<EXPECTED_IP_SHA256>' --nft-sha256 '<EXPECTED_NFT_SHA256>' --sysctl-sha256 '<EXPECTED_SYSCTL_SHA256>' --tc-sha256 '<EXPECTED_TC_SHA256>' --apply
./build/vpnctl network-check
```

Для fresh installed-kernel readback используется `network-check --native-check` **с теми же полными topology и expected scope/hash flags для соответствующего сервера**. До создания namespace/guard такой check должен остановиться; prepared artifact не делает его positive. `network-apply --apply` принимает тот же набор independent flags, но запускает network mutation и требует отдельного разрешённого native стенда/recovery acceptance. Эти команды не являются проверенным двухсерверным deploy и не запускают ядра.

## Kernel граница и условия apply

RU namespace разрешает external original traffic только к independently selected Foreign IPv4 TCP443. Отдельный IPv4 loopback exception нужен SOCKS association и fixed camouflage relay; он не открывает external UDP, DNS или direct HTTPS к camouflage target. Ingress — TCP443; приватные/metadata/management destinations и IPv6 запрещены. Foreign принимает TCP443 только от выбранного RU и выпускает public IPv4 TCP/UDP, запрещая private/reserved/metadata, оба VPS и current local host addresses.

Host plan отделяет namespace от host input, ограничивает actual и conntrack original tuples до/после DNAT/SNAT, не добавляет blanket established accept для namespace. Это защищает также от destination rewrite, которое иначе могло бы открыть host management. Owned nft tables добавляются без `flush ruleset`; unrelated host rules, routes и SSH не должны изменяться.

Apply повторяет fresh inventory, config binding, protected helper identity и expected scope; устанавливает guard **до** link activation и повторяет readback перед каждым UP. Промежуточные проверки допускают только ожидаемые ещё отсутствующие connected/loopback/default routes; default route добавляется после UP, final check требует полный exact topology. Namespace topology, filters/NAT, sysctls, policy routing и TC проверяются вместе; legacy iptables, неподдержанный TC/XDP, unowned packet rewrite/flow offload или нестандартные policy routes блокируют mutation. Сохранившийся файл или успешный helper exit не являются installed proof. Приватный proof с TTL10s привязан к held namespace descriptor и не восстанавливается из JSON. `kernel_guard_verified` относится к текущему принятому nft/topology/readback subset; `native_acceptance`, `client_verified` и `ready` остаются false. TTL proof не является guard lease: будущий core launcher должен повторить актуальные guards перед запуском.

Если исходный host `net.ipv4.ip_forward=0`, mutation блокируется **до записи**. Переключение forwarding сбрасывает IPv4 host/router defaults; сохранение и восстановление all/default/interface sysctls и NIC LRO пока не реализовано. Нельзя обходить blocker скрытым bootstrap или ручной командой из этого runbook.

Exclusive private `network-staging/apply.json` journal хранит bounded canonical последовательность шагов, связанную с manifest, и сохраняется при ошибке/прерывании. Автоматического resume или replay нет: partial operation требует independently checked recovery. Идемпотентный повтор требует complete journal **и fresh full readback**, а не одного исторического success. Guards/чужие объекты не удаляются автоматически; journal не является kernel/profile proof.

## Что остаётся до первого подключения

Нужен разрешённый Linux стенд с actual positive/negative nft JSON readback и recovery tests, затем dedicated unprivileged core runtime с guard-before-start/restart ordering и current vault-bound client profile. Проверить actual REALITY relay/handshake, Android exact import, DNS/TCP/UDP, потерю Foreign без RU fallback, private/metadata/host/IPv6 reachability и RAM/restart на обоих VPS. Parser checks на pinned Windows Xray/sing-box и cross-compile этого не заменяют. Ни runtime process launcher, ни service activation, ни production/client acceptance эта инструкция не обещает.
