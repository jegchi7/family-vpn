<script lang="ts">
 import type {Instruction} from './api';
 let {guides}:{guides:Instruction[]}=$props();let selectedOS=$state('ios');
 const systems:Record<string,string>={ios:'iPhone / iPad',android:'Android',windows:'Windows',macos:'macOS',linux:'Linux',other:'Другое'};
</script>

<header><div class="eyebrow">БЫСТРЫЙ СТАРТ</div><h1>Как подключиться</h1><p>Выберите ОС вручную. Памятку можно сохранить заранее и открыть без интернета.</p></header>
<div class="platforms" aria-label="Операционная система">{#each Object.entries(systems) as [os,label]}<button class:active={selectedOS===os} onclick={()=>selectedOS=os}>{label}</button>{/each}</div>
{#if guides.filter(g=>g.os===selectedOS).length===0}<p>Для этой ОС проверенных инструкций пока нет.</p>{/if}
<div class="guide-list">{#each guides.filter(g=>g.os===selectedOS) as guide}<article class="guide" aria-label={guide.title}>
 <span class="pill" class:pending={!guide.verified}>{guide.verified&&guide.verification_scope==='portal'?'Проверен сценарий кабинета':guide.verified?'Проверен клиент':'Черновик · проверка на устройстве впереди'}</span>
 <h2>{guide.title}</h2>
 {#if guide.content_version}<p class="guide-meta">Версия памятки: {guide.content_version}{guide.verified_at?` · Проверено: ${guide.verified_at}`:''}</p>{/if}
 {#if guide.verification_scope==='portal'}<p class="guide-meta">Совместимость VPN-приложений проверяется отдельно.</p>{/if}
 {#if guide.kind==='vpn'&&!guide.verified}<p class="guide-meta">Проверенная установка и автоматический импорт пока недоступны.</p>{/if}
 <ol>{#each guide.steps as step}<li>{step}</li>{/each}</ol>
 {#if guide.offline_available}<a class="download" href={`/api/v1/instructions/${encodeURIComponent(guide.id)}/offline`} download>Скачать офлайн-памятку ↓</a>{/if}
</article>{/each}</div>

<style>.guide-list{display:grid;gap:16px}.guide-meta{font-size:12px;color:#738278;line-height:1.6}.guide-list .download{display:inline-block;white-space:normal;line-height:1.5}.guide-list h2,.guide-list li{overflow-wrap:anywhere}</style>
