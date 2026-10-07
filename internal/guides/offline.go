package guides

import (
	"bytes"
	"familyvpn.local/platform/internal/domain"
	"html/template"
)

var offline = template.Must(template.New("offline").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>{{.Title}} · Семейный VPN</title>
<style>body{font:16px/1.7 system-ui,sans-serif;background:#f4f5f7;color:#203a30;margin:0}main{max-width:760px;margin:auto;padding:28px 20px}article{background:white;border:1px solid #dce5de;border-radius:16px;padding:24px}h1{font-size:28px;line-height:1.3}li{margin:16px 0}small{color:#65766c}p,li,h1{overflow-wrap:anywhere}.notice{padding:16px;background:#edf3ed;border-radius:10px}footer{margin-top:24px;font-size:13px}ol{padding-left:24px}</style></head>
<body><main><small>СЕМЕЙНЫЙ VPN · ОФЛАЙН-ПАМЯТКА · {{.OS}} · версия {{.ContentVersion}}</small><h1>{{.Title}}</h1>
<p class="notice">{{if .Verified}}{{if eq .VerificationScope "portal"}}Проверен сценарий кабинета: {{.VerifiedAt}}. Совместимость VPN-приложений проверяется отдельно.{{else}}Проверен клиент {{.AppID}} {{.AppVersion}}: {{.VerifiedAt}}.{{end}}{{else}}Черновик: совместимость приложения и способ импорта ещё не проверены.{{end}}</p>
<article><ol>{{range .Steps}}<li>{{.}}</li>{{end}}</ol></article>
<footer>Эта памятка открывается без интернета и кабинета. Здесь нет ключей, конфигов, адреса вашей панели или персональных данных. Сохранение памятки не устанавливает VPN.</footer></main></body></html>`))

func Render(g domain.Instruction) ([]byte, error) {
	var b bytes.Buffer
	if e := offline.Execute(&b, g); e != nil {
		return nil, ErrCatalog
	}
	return b.Bytes(), nil
}
