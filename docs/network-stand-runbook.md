# RU ingress и изоляция двух серверов

v0.29 продолжает закрытую конфигурацию RU ingress и operator-only инструменты подготовки `vpn-data`: сохранение проверенного forwarding baseline0 и ограниченная совместимость Foreign с существующим Docker/Amnezia. Начальное RU staging содержит **пустой список клиентов**. Подготовка, проверка синтаксиса и kernel readback не разрешают скачивание профиля и не переводят его в `ready`. На VPS из локальной разработки никто не подключался; службы VPN, firewall, routes и SSH здесь не менялись. Native Ubuntu20.04 и Android acceptance остаются открыты. Это контракт локальной реализации, не проверенный сценарий deployment.

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

Для Foreign с legacy iptables оператор дополнительно задаёт `--xtables-legacy-sha256 '<EXPECTED_XTABLES_LEGACY_SHA256>'` для фиксированного protected `/usr/sbin/xtables-legacy-multi`. Флаг не выбирает произвольный executable/backend и на RU запрещён. Без него любое наличие legacy tables остаётся blocker. Fixed multicall читает **обе** legacy семьи через `iptables-save`/`ip6tables-save`; полный nft JSON читается независимо. Default `iptables-save` через alternatives не является проверкой отсутствия другого backend. Fixed `-M /proc/0/exe` запрещает запуск настроенного modprobe при ошибке; дополнительные executable/module paths оператор не передаёт. Owned legacy writes имеют bounded `-w 2`.

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

`network-staging` содержит canonical manifestformat2 и exact generated host/namespace nft plans. Manifest хранит только digests ожидаемого поведения forwarding/shared firewall и факт необходимости двух owned shared-chain правил; raw sysctls/features/iptables snapshot и restore commands не сохраняются. Старое staging не преобразуется автоматически и не перезаписывается. Для Foreign туда дополнительно попадает новый private `foreign-xray.json`: adapter сначала проверяет original pair, затем меняет **только** DNS `UseIPv4` и freedom `ForceIPv4`. Credentials, peer, source и deny rules сохранены; IPv6 endpoint/source/camouflage rejected. Original pair остаётся отдельно и никогда не autoupgrade/rewrite.

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

Если Foreign staging подготовлено с legacy pin, этот же флаг обязателен при apply/native-check. Его добавление после staging не меняет записанный target: потребуется отдельно проверенная новая подготовка. Примеры выше не доказывают совместимость установленного Docker backend и не являются командами активации имеющихся VPS.

## Kernel граница и условия apply

RU namespace разрешает external original traffic только к independently selected Foreign IPv4 TCP443. Отдельный IPv4 loopback exception нужен SOCKS association и fixed camouflage relay; он не открывает external UDP, DNS или direct HTTPS к camouflage target. Ingress — TCP443; приватные/metadata/management destinations и IPv6 запрещены. Foreign принимает TCP443 только от выбранного RU и выпускает public IPv4 TCP/UDP, запрещая private/reserved/metadata, оба VPS и current local host addresses.

Host plan отделяет namespace от host input, ограничивает actual и conntrack original tuples до/после DNAT/SNAT, не добавляет blanket established accept для namespace. Это защищает также от destination rewrite, которое иначе могло бы открыть host management. Owned nft tables добавляются без `flush ruleset`; existing Docker policy/entries, unrelated routes и SSH не удаляются и не переписываются. При необходимости меняется только начало общего `ip filter FORWARD`: добавляются два точно проверяемых owned interface ACCEPT, описанных ниже.

Apply повторяет fresh inventory, config binding, protected helper identity и expected scope; устанавливает guard **до** link activation и повторяет readback перед каждым UP. Промежуточные проверки допускают только ожидаемые ещё отсутствующие connected/loopback/default routes; default route добавляется после UP, final check требует полный exact topology. Namespace topology, filters/NAT, sysctls, policy routing и TC проверяются вместе; неподдержанный TC/XDP, packet rewrite/flow offload или нестандартные policy routes блокируют mutation. Legacy rules допустимы только в закрытом Foreign subset с independent pin и fresh обеих families readback. Сохранившийся файл или успешный helper exit не являются installed proof. Приватный proof с TTL10s привязан к held namespace descriptor и не восстанавливается из JSON. `kernel_guard_verified` относится к текущему принятому nft/topology/readback subset; `native_acceptance`, `client_verified` и `ready` остаются false. TTL proof не является guard lease: будущий core launcher должен повторить актуальные guards перед запуском.

### Forwarding baseline0

При исходном `net.ipv4.ip_forward=0` подготовка и apply снимают закрытый полный IPv4 devconf vector для `all`, `default` и каждого текущего интерфейса; scope, ifindex, procfs identity и feature vectors проверяются повторно. Raw baseline остаётся только в trusted process memory. Для записи используются заранее удерживаемые protected procfs descriptors с проверкой исходной identity, а не повторный поиск изменяемого пути.

Поддерживается только исходное отсутствие IPv4 forwarding на всех существующих non-loopback интерфейсах. Для каждого интерфейса необходим проверенный feature vector, `rx-lro` в состояниях requested=0 и active=0, без pending изменения других доступных mutable features. Unknown/missing devconf keys, неподдержанный UAPI/feature layout, нестабильный interface/scope или активный/requested LRO блокируют процедуру; offload flags автоматически не переключаются. Неизвестный драйвер/ядро не считается совместимым из-за successful cross-build.

Feature state читается тремя закрытыми GET ethtool UAPI commands для Linux amd64/arm64; произвольный ioctl, SET/offload command, ethtool executable или pointer оператор не задаёт. Kernel/driver `begin`/`complete` callbacks могут выполняться даже на GET: отсутствие любых driver effects и hard timeout для зависшего ioctl не обещаются. Context/scope проверяются до и после вызова; read error блокирует последующую mutation. Reviewed Linux5.4/5.15 source subset не является hardware/native acceptance.

До глобального переключения устанавливается host nft guard, сохраняющий DROP для **всего unrelated forwarding** baseline0. Закрытая последовательность включает global `ip_forward=1`, восстановление прежнего `default.forwarding`, `all.accept_redirects` и forwarding остальных исходных интерфейсов. Значения global/all.forwarding=1, forwarding выбранного uplink=1 и нового owned veth=1 намеренно нужны новому data пути; они не обещают прежние router semantics uplink. Все остальные reviewed devconf/feature значения должны точно совпасть. Guard проверяется перед каждой записью и после группы; full observation повторяется перед и после каждой записи; unexpected дополнительный сброс или изменение прекращает операцию.

При отмене/ошибке нет inverse toggle, blind rollback, persistent raw baseline или replay restoration после restart. Guard/journal сохраняются для checked recovery. Expected fingerprint используется только для повторного **read-only** сравнения полного subset; он не восстанавливает значения и не заменяет actual management/forwarding acceptance. Если baseline уже1, закрытая процедура baseline0 не выполняется; independent current guards всё равно обязательны.

### Foreign Docker/Amnezia subset

Сведения владельца: существующий Amnezia container публикует UDP30759, а `docker0` и `amn0` имеют отдельные private CIDR. Runtime не обращается к Docker API/socket, не останавливает контейнеры и не удаляет bridge/NAT rules. Реальные bridge kind, текущие address/route inventories и отсутствие пересечения с выбранным `/30` читаются native-bound helper заново.

Разрешён только проверяемый IPv4 `ip/nat` / legacy nat subset: positive source CIDR внутри одного independently observed private bridge для MASQUERADE/SNAT; фиксированный UDP30759 DNAT к адресу того же bridge; entry jump в DOCKER только с LOCAL destination condition. Hairpin recipes также закрыты bridge/local-source условиями. Название DOCKER само по себе ничего не разрешает. Our TCP443 ingress и source namespace `/30` не могут попасть в эти разрешённые rewrite recipes. Host namespace guard запрещает все local/private/management destinations до destination NAT. IPv6 namespace traffic остаётся запрещённым.

Docker `FORWARD` default DROP требует отдельной границы reachability. После установки host+namespace guard и до первого UP можно добавить ровно два leading IPv4 ACCEPT с `iif=fvpn-host` и `oif=fvpn-host` в стандартный shared `filter/FORWARD` соответствующего backend. Для legacy это fixed pinned multicall; для nft — fixed native helper. Более поздний independently owned nft forward guard остаётся обязательным и отбрасывает непринятые tuples; early shared ACCEPT не перекрывает его DROP. Unrelated traffic не matches owned interface и проходит прежнюю Docker policy. Partial insertion не активирует link/core.

Перед activation требуется exact readback двух правил в начале chain без дополнительных predicates, duplicate/ordered aliases и с неизменным semantic digest **всех остальных** shared rules/chains/policies. Dump timestamps/metainfo, validated handles и изменяющиеся counters не входят в digest; named counter identity и все остальные predicates/verdicts/order сохраняются. Docker restart/shared writer, удаливший/переместивший owned rules или изменивший policy, прекращает positive check. Из сохранённого digest нельзя восстановить rules или сделать ready.

Opaque nft `xt` statements, произвольные NAT/ports/bridges, marks, CT assignments/zone overrides, queue, offload и unknown targets продолжают блокироваться. Legacy IPv6 NAT не поддерживается; публикация `:::30759` сама по себе не доказывает, что IPv6 ruleset попадает в разрешённый subset. Совместимость фактического Foreign backend и отсутствие влияния на existing AWG требуют actual Linux packet/restart/management tests. Local synthetic comparators не являются native Docker acceptance.

Exclusive private `network-staging/apply.json` journal хранит bounded canonical последовательность шагов, связанную с manifest, и сохраняется при ошибке/прерывании. Автоматического resume или replay нет: partial operation требует independently checked recovery. Идемпотентный повтор требует complete journal **и fresh full readback**, а не одного исторического success. Guards/чужие объекты не удаляются автоматически; journal не является kernel/profile proof.

## Что остаётся до первого подключения

Нужен разрешённый Linux стенд с actual positive/negative nft JSON readback и recovery tests, затем dedicated unprivileged core runtime с guard-before-start/restart ordering и current vault-bound client profile. Проверить actual REALITY relay/handshake, Android exact import, DNS/TCP/UDP, потерю Foreign без RU fallback, private/metadata/host/IPv6 reachability и RAM/restart на обоих VPS. Parser checks на pinned Windows Xray/sing-box и cross-compile этого не заменяют. Ни runtime process launcher, ни service activation, ни production/client acceptance эта инструкция не обещает.
