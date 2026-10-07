<script lang="ts">
 import {onMount} from 'svelte';
 import {api,type Device} from './api';
 import type {components} from './api.generated';
 let {devices,csrf,onchange}:{devices:Device[];csrf:string;onchange:(items:Device[])=>void}=$props();
 let quota=$state<components['schemas']['DeviceQuota']|null>(null);
 let showForm=$state(false);let name=$state('');let os=$state<components['schemas']['DeviceRequest']['os']>('ios');let requestID=$state('');
 let busy=$state(false);let error=$state('');let notice=$state('');let editID=$state('');let editName=$state('');let editRevision=$state(0);let cancelID=$state('');
 const systems:Record<string,string>={ios:'iPhone / iPad',android:'Android',windows:'Windows',macos:'macOS',linux:'Linux',other:'Другое'};
 const states:Record<string,string>={pending:'Ожидает настройки',active:'Профили настроены',partial:'Настроено частично',revoking:'Отзыв выполняется',revoked:'Закрыто',error:'Требует внимания'};
 function importedPending(profile:components['schemas']['Profile']){return profile.state==='pending'&&(profile.format==='vless-reality-uri'||profile.format==='awg-3.1-conf');}
 async function refresh(){const [list,q]=await Promise.all([api.devices(),api.deviceQuota()]);onchange(list.items);quota=q;}
 async function reload(){busy=true;error='';try{await refresh();editID='';cancelID='';}catch(e){error=e instanceof Error?e.message:'Не удалось обновить список';}finally{busy=false;}}
 onMount(()=>{void reload();});
 async function create(event:SubmitEvent){
  event.preventDefault();busy=true;error='';notice='';requestID ||= crypto.randomUUID();
  try{await api.requestDevice({request_id:requestID,name,os},csrf);requestID='';name='';showForm=false;notice='Заявка сохранена. Профили появятся после настройки администратором.';await refresh();}
  catch(e){error=e instanceof Error?e.message:'Не удалось отправить заявку';}finally{busy=false;}
 }
 function edit(d:Device){editID=d.id;editName=d.name;editRevision=d.revision;cancelID='';error='';notice='';}
 async function rename(event:SubmitEvent){
  event.preventDefault();busy=true;error='';notice='';
  try{await api.renameDevice(editID,{name:editName,expected_revision:editRevision},csrf);editID='';notice='Название сохранено.';await refresh();}
  catch(e){error=e instanceof Error?e.message:'Не удалось сохранить название';}finally{busy=false;}
 }
 async function cancel(d:Device){
  busy=true;error='';notice='';try{await api.cancelDevice(d.id,{expected_revision:d.revision},csrf);cancelID='';notice='Заявка отменена. Слот устройства освобождён.';await refresh();}
  catch(e){error=e instanceof Error?e.message:'Не удалось отменить заявку';}finally{busy=false;}
 }
</script>
<section aria-label="Устройства и заявки">
 <div class="section-title"><h2>Мои устройства</h2><span>{quota?`Занято ${quota.used} из ${quota.limit}`:'Загружаем лимит…'}</span></div>
 <div class="device-actions"><button class="primary" disabled={busy||!quota||quota.remaining===0} onclick={()=>{showForm=!showForm;error='';}}>{showForm?'Скрыть форму':'Добавить устройство'}</button><button disabled={busy} onclick={reload}>Обновить список</button></div>
 {#if quota?.remaining===0}<p class="form-hint">Свободных слотов нет. Можно отменить ещё не выданную заявку или обратиться к администратору.</p>{/if}
 {#if error}<p role="alert" class="error">{error}</p>{/if}
 {#if notice}<p role="status" class="auth-notice">{notice}</p>{/if}
 {#if showForm}<section class="auth-panel"><h3>Новое устройство</h3><p>Сохраните заявку на основной AWG и резервный REALITY. Сейчас это локальный стенд: серверные ключи и конфиги ещё не создаются.</p>
  <form onsubmit={create}><label for="device-name">Название устройства</label><input id="device-name" bind:value={name} required maxlength="64" disabled={busy} placeholder="Например, мой iPhone"/>
   <label for="device-os">Операционная система</label><select id="device-os" bind:value={os} disabled={busy}>{#each Object.entries(systems) as [value,label]}<option {value}>{label}</option>{/each}</select>
   <button class="primary" type="submit" disabled={busy||quota?.remaining===0}>{busy?'Сохраняем…':'Сохранить заявку'}</button>
  </form></section>{/if}
 {#if devices.length===0}<section class="guide"><h2>Устройств пока нет</h2><p>Добавьте своё устройство. До настройки профилей заявка будет ожидать администратора.</p></section>{/if}
 <div class="device-grid">
 {#each devices as device (device.id)}<article class="device-card" aria-label={device.name}>
  <div class="card-top"><span class="device-icon">{device.os==='ios'||device.os==='android'?'▯':'▱'}</span><span class="pill" class:pending={device.state!=='active'}>{states[device.state]??device.state}</span></div>
  <h3>{device.name}</h3><p class="muted">{systems[device.os]??device.os}</p>
  <div class="profiles">{#each device.profiles as profile}<div class="profile"><div><strong>{profile.protocol==='awg'?'Основной':'Резервный'}</strong><small>{profile.protocol==='awg'?'AmneziaWG':'REALITY'}</small></div><span class="muted">{profile.state==='revoked'?'Закрыт':profile.state==='ready'?'Подготовлен':importedPending(profile)?'Сохранён, ждёт сверки':'Ожидает'}</span></div>{/each}</div>
  <p class="card-note">{device.state==='pending'?(device.profiles.some(importedPending)?'Конфиг сохранён. Администратор ещё не подтвердил его установку на сервере.':'Рабочий доступ ещё не выдан.'):device.state==='revoked'?'Запись закрыта. Для нового устройства создайте новую заявку.':'Готовность профиля не означает подключение устройства.'}</p>
  {#if editID===device.id}<form onsubmit={rename} class="device-inline"><label for={'rename-'+device.id}>Новое название</label><input id={'rename-'+device.id} bind:value={editName} required maxlength="64" disabled={busy}/><div class="device-actions"><button class="primary" disabled={busy} type="submit">Сохранить название</button><button disabled={busy} type="button" onclick={()=>editID=''}>Закрыть</button></div></form>
  {:else if device.state!=='revoked'&&device.state!=='revoking'}<div class="device-actions"><button disabled={busy} onclick={()=>edit(device)}>Переименовать</button>{#if device.state==='pending'&&device.profiles.every(p=>p.format==='')}<button disabled={busy} onclick={()=>{cancelID=device.id;error='';}}>Отменить заявку</button>{/if}</div>{/if}
  {#if cancelID===device.id}<div class="callout"><p>Отменить заявку «{device.name}»? Это доступно только пока серверные профили не выдавались.</p><div class="device-actions"><button disabled={busy} onclick={()=>cancel(device)}>Да, отменить</button><button disabled={busy} onclick={()=>cancelID=''}>Оставить</button></div></div>{/if}
 </article>{/each}
 </div>
</section>
<style>
 .device-actions{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}.device-actions button{max-width:100%;min-height:44px;padding:10px 14px;border:1px solid #b7c9c5;border-radius:8px;font:inherit;cursor:pointer}.device-actions button:not(.primary){background:#fff;color:#24463f}.device-actions button:disabled{opacity:.55;cursor:default}.device-inline{display:grid;gap:10px;margin-top:16px}.device-inline input,select{width:100%;min-width:0;padding:12px;border:1px solid #b7c9c5;border-radius:8px;background:white;font:inherit;color:inherit;box-sizing:border-box}select{margin-bottom:16px}.device-card{min-width:0}.device-card h3{overflow-wrap:anywhere}
</style>
