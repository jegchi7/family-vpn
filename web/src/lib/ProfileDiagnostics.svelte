<script lang="ts">
 import {onMount} from 'svelte';
 import type {components} from './api.generated';
 let {diagnostics,stored=false}:{diagnostics?:components['schemas']['ProfileDiagnostics'];stored?:boolean}=$props();
 let now=$state(Date.now());
 const labels:Record<string,string>={unchecked:'Проверка не выполнена',stored:'Сохранена, ждёт сверки',matched:'Совпадает по сверке',conflict:'Обнаружено расхождение',expired:'Результат устарел',stale:'Нужна новая сверка'};
 const sources:Record<string,string>={snapshot:'Сверка с сохранённой копией',native_readback:'Сверка с прочитанными настройками'};
 const receivedAt=$derived.by(()=>{void diagnostics;return Date.now();});
 const checked=$derived(diagnostics?.checkedAt?Date.parse(diagnostics.checkedAt):NaN);
 const expires=$derived(diagnostics?.expiresAt?Date.parse(diagnostics.expiresAt):NaN);
 const validTime=$derived(Number.isFinite(checked)&&Number.isFinite(expires)&&expires>checked&&expires-checked<=60000);
 const configuration=$derived.by(()=>{
  const state=diagnostics?.configuration??(stored?'stored':'unchecked');
  if(state!=='matched'&&state!=='conflict')return state;
  if(!validTime||!sources[diagnostics?.source??'none'])return 'unchecked';
  if(checked>receivedAt||checked>now)return 'stale';
  if(now>=expires)return 'expired';
  return state;
 });
 const checkedLabel=$derived(validTime&&checked<=now?new Date(checked).toLocaleString('ru-RU'):null);
 onMount(()=>{const timer=setInterval(()=>{now=Date.now();},1000);return()=>clearInterval(timer);});
</script>

<section class="diagnostics" aria-label="Подключение и проверки протокола">
 <div class="diagnostic-row"><span>Подключение</span><strong class="status neutral"><span class="status-dot" aria-hidden="true"></span>Нет данных</strong></div>
 <div class="diagnostic-row"><span>Конфигурация</span><strong class="status" class:match={configuration==='matched'} class:conflict={configuration==='conflict'} class:attention={['stored','expired','stale'].includes(configuration)} class:neutral={configuration==='unchecked'}><span class="status-dot" aria-hidden="true"></span>{labels[configuration]??labels.unchecked}</strong></div>
 {#if diagnostics&&sources[diagnostics.source]}<p class="result-source">{sources[diagnostics.source]}{#if checkedLabel}<span> · <time datetime={diagnostics.checkedAt}>{checkedLabel}</time></span>{/if}</p>{/if}
 <details class="protocol-checks"><summary>Проверки подключения</summary><dl><div><dt>VPN-клиент</dt><dd>Не проверен</dd></div><div><dt>Передача данных</dt><dd>Не проверена</dd></div><div><dt>DNS и маршрут</dt><dd>Не проверены</dd></div></dl><p>Сверка конфигурации не подтверждает подключение. Нужна проверка с вашего устройства.</p></details>
</section>

<style>
 .diagnostics{margin:0 0 16px;padding:13px;background:#f7f9f8;border:1px solid #e4eae7;border-radius:10px;min-width:0;color:#42544c;font-size:11px;line-height:1.5}.diagnostic-row{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin:0 0 9px}.diagnostic-row>span{padding-top:3px;flex-shrink:0}.status{display:inline-flex;align-items:center;gap:6px;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:600;text-align:right;overflow-wrap:anywhere;max-width:100%;color:#52625b;background:#e9eeeb}.status-dot{width:6px;height:6px;flex-shrink:0;border-radius:50%;background:currentColor}.match{color:#216049;background:#dfefe6}.conflict{color:#963829;background:#f9e4df}.attention{color:#77550e;background:#f7edd5}.neutral{color:#52625b;background:#e9eeeb}.result-source{font-size:10px;line-height:1.6;color:#62756a;margin:2px 0 10px;overflow-wrap:anywhere}.protocol-checks{border-top:1px solid #e1e7e3;padding-top:9px}.protocol-checks summary{cursor:pointer;color:#3e6253;min-height:24px;padding:3px 0}.protocol-checks summary:focus-visible{outline:3px solid #12695d;outline-offset:3px}.protocol-checks dl{margin:10px 0}.protocol-checks dl>div{display:flex;justify-content:space-between;gap:12px;padding:3px 0}.protocol-checks dd{margin:0;text-align:right;color:#6b776f}.protocol-checks p{font-size:10px;margin:8px 0 0;color:#62756a;line-height:1.6}@media(max-width:400px){.diagnostic-row{flex-wrap:wrap;gap:4px}.diagnostic-row .status{margin-left:auto}.diagnostics{padding:11px}}
</style>
