# Gateway schemas

`envelope-v1.schema.json` — **draft metadata envelope**, не production protocol. В runtime не импортируется и не обслуживается по HTTP. Для реальной реализации нужны tagged protocol parameters, secret delivery, TLS identity/certificate lifecycle, signature для offline файла и strict schema validation. `secret_ref` — идентификатор объекта конкретной ревизии/узла, не разрешение скачать произвольный URL или открыть файл.

До GW-01/03 схема может меняться без обещания wire compatibility. Требование `previous_revision < revision`, проверка времени, sender/recipient и monotonic state реализуются в будущей семантической валидации; JSON Schema не доказывает их автоматически.
