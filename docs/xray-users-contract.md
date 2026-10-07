# Xray users readback · source contract v0.19

Upstream XTLS/Xray-core inspected 05.10.2026 at commit **7da5dae6502b787fc6d903863e9a6c5043d107a2**. Это source inspection, не pin установленного binary/responding core и не native compatibility acceptance.

| Файл | SHA256 inspected bytes |
|---|---|
| main/commands/all/api/inbound_user.go | ebe3a8fa50afbb93f488e1b108fb3a70518dc10c1af13d93b46e0bc19ff6d730 |
| main/commands/all/api/shared.go | 3392b495bc87354b9432447fa69b202cd91e713d74d85f524901ae12eebcbe1f |
| app/proxyman/command/command.go | 878c68afc879952d4692d9634a295a8983493ba2eda16339fdd9fbb4e9716cc7 |
| app/proxyman/command/command.proto | 4b3e4e9ad1488af54429ef6a3948fc4d527033a526280d708e389883e264e7b0 |
| common/reflect/marshal.go | 6c40bd8c4d55a646c03122c050492d1b38b1c43e19ad3cc25805d4bfa05c8a23 |
| common/protocol/user.proto | 33e5c5ea3cbf330e7c526c6b0c93bc8f07a3f8b4cad579bf50698e3c544270e5 |
| proxy/vless/account.proto | 1e03384298211ee21e666cf8a80f50eba16a3c054fdc07a4da13fe67d9b71dac |
| proxy/vless/account.go | 018cc5ea029ef6e41a026c2cd9bc951f9f80868146f366e1e5fe2e7a24d3dd0f |
| proxy/vless/validator.go | eefa673c150a04392e1c98891894afef2b60c0146350460b4bc00c7fb42ee336 |

Primary source links: [inbound_user.go](https://github.com/XTLS/Xray-core/blob/7da5dae6502b787fc6d903863e9a6c5043d107a2/main/commands/all/api/inbound_user.go), [shared.go](https://github.com/XTLS/Xray-core/blob/7da5dae6502b787fc6d903863e9a6c5043d107a2/main/commands/all/api/shared.go), [HandlerService](https://github.com/XTLS/Xray-core/blob/7da5dae6502b787fc6d903863e9a6c5043d107a2/app/proxyman/command/command.go), [marshal.go](https://github.com/XTLS/Xray-core/blob/7da5dae6502b787fc6d903863e9a6c5043d107a2/common/reflect/marshal.go), [account.proto](https://github.com/XTLS/Xray-core/blob/7da5dae6502b787fc6d903863e9a6c5043d107a2/proxy/vless/account.proto), [validator.go](https://github.com/XTLS/Xray-core/blob/7da5dae6502b787fc6d903863e9a6c5043d107a2/proxy/vless/validator.go). [Official API configuration](https://xtls.github.io/en/config/api.html).

inbounduser вызывает GetInboundUsers с explicit tag и пустым email; handler получает current UserManager.GetUsers. CLI custom reflector раскрывает TypedMessage с _TypedMessage_=xray.proxy.vless.Account, не protojson/base64 value. User fields email/level/account; account subset id/flow/encryption. Unknown fields/types/duplicate keys/wire IDs/nulls/trailing JSON/depth>32/output>64KiB/users>256 отвергаются. Дополнительные encrypted/reverse account fields не принимаются автоматически.

Current VLESS validator GetAll читает email map: unnamed entries не перечисляются. ProcessUUID обнуляет bytes6/7 для lookup; exact exported UUID сохраняется, но uniqueness учитывает все aliases. API list не является полным inventory и не подтверждает отсутствие/отзыв unnamed peer. Меняющийся sync.Map order нормализуется до сравнения.

ListInbounds исследован отдельно: он возвращает receiver/proxy settings, это не использовано как доказательство current users/complete installed-access. Users-only observer не проверяет transport/REALITY/endpoint/actual core identity/revision/client connection. Loopback API не аутентифицирует responder; самостоятельный tool pin не устраняет эту границу. Перед расширением нужны actual manifest, version-specific round-trip и разрешённый operational stand.
