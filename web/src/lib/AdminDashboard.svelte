<script lang="ts">
 import {onMount} from 'svelte';
 import {api} from './api';
 import type {components} from './api.generated';
 let {onrefresh}:{onrefresh:()=>Promise<void>}=$props();
 let view=$state('devices');let filter=$state('pending');let busy=$state(false);let error=$state('');let cursor=$state('');let page=$state(1);
 let users=$state<components['schemas']['AdminUser'][]>([]);let devices=$state<components['schemas']['AdminDevice'][]>([]);let audit=$state<components['schemas']['AdminAuditEvent'][]>([]);
 const states:Record<string,string>={all:'Все состояния',pending:'Ожидает настройки',active:'Настроено',partial:'Настроено частично',revoking:'Отзыв выполняется',revoked:'Закрыто',error:'Требует внимания',invited:'Ожидает приглашения',disabled:'Отключён'};
 const invitations:Record<string,string>={available:'Приглашение действует',expired:'Приглашение истекло',used:'Приглашение использовано',none:'Приглашения нет'};
 const actions:Record<string,string>={'invite.create':'Создано приглашение','invite.accept':'Принято приглашение','invite.reissue':'Приглашение перевыпущено','session.login':'Вход в кабинет','session.logout':'Выход из кабинета','recovery.issue':'Выдано восстановление','recovery.complete':'Доступ восстановлен','device.request':'Заявка устройства','device.rename':'Устройство переименовано','device.cancel':'Заявка отменена','profile.stage':'Конфиг сохранён','profile-vault.initialize':'Хранилище инициализировано','profile-vault.rotate':'Ключ хранилища заменён',other:'Другое действие'};
 async function load(next=false){
  if(busy)return;busy=true;error='';const after=next?cursor:'';
  try{
   if(view==='users'){const result=await api.adminUsers(after);users=result.items;cursor=result.next_cursor;}
   else if(view==='devices'){const result=await api.adminDevices(filter,after);devices=result.items;cursor=result.next_cursor;}
   else{const result=await api.adminAudit(after);audit=result.items;cursor=result.next_cursor;}
   await onrefresh();page=next?page+1:1;
  }catch(e){error=e instanceof Error?e.message:'Не удалось прочитать данные';}
  finally{busy=false;}
 }
 function select(next:string){view=next;cursor='';page=1;users=[];devices=[];audit=[];void load();}
 onMount(()=>{void load();});
</script>

<section class="admin-data" aria-label="Административные данные">
 <div class="platforms" aria-label="Данные администратора">
  <button class:active={view==='devices'} disabled={busy} onclick={()=>select('devices')}>Заявки и устройства</button>
  <button class:active={view==='users'} disabled={busy} onclick={()=>select('users')}>Пользователи</button>
  <button class:active={view==='audit'} disabled={busy} onclick={()=>select('audit')}>Журнал действий</button>
 </div>
 <div class="admin-toolbar">
  {#if view==='devices'}<label>Состояние устройства <select bind:value={filter} disabled={busy} onchange={()=>load()}>{#each ['pending','all','active','partial','revoking','revoked','error'] as value}<option {value}>{states[value]}</option>{/each}</select></label>{/if}
  <button disabled={busy} onclick={()=>load()}>Обновить список</button>
 </div>
 {#if busy}<p role="status">Читаем данные…</p>{/if}
 {#if error}<div class="error" role="alert"><p>{error}</p><button disabled={busy} onclick={()=>load()}>Повторить</button></div>{/if}
 {#if !error}
  {#if view==='devices'}
   <h2>Заявки и устройства</h2>
   {#if !busy&&devices.length===0}<p class="muted">В выбранном состоянии устройств нет.</p>{/if}
   <div class="admin-list">{#each devices as d}<article class="device-card" aria-label={d.name}>
    <div class="card-top"><h3>{d.name}</h3><span class="pill pending">{states[d.state]}</span></div>
    <p>{d.owner_login} · {d.os} · поколение {d.generation}</p>
    <div class="profiles">{#each d.profiles as p}<div class="profile"><strong>{p.protocol==='awg'?'AmneziaWG':'REALITY'}</strong><span class="muted">{p.state==='pending'?(p.stored?'Сохранён, ждёт сверки':'Ждёт импорта'):p.state==='ready'?'Готовность записана':states[p.state]??'Требует внимания'}</span></div>{/each}</div>
    <details><summary>Идентификаторы для настройки</summary><dl><dt>Владелец</dt><dd><code>{d.owner_id}</code></dd><dt>Устройство</dt><dd><code>{d.id}</code></dd><dt>Ревизия</dt><dd>{d.revision}</dd>{#each d.profiles as p}<dt>{p.protocol} profile</dt><dd><code>{p.id}</code></dd>{/each}</dl></details>
   </article>{/each}</div>
   <p class="footnote">Сохранённый конфиг ещё ждёт проверки установки и подключения. Состояние устройства не подтверждает, что оно сейчас в сети.</p>
  {:else if view==='users'}
   <h2>Пользователи</h2>
   {#if !busy&&users.length===0}<p class="muted">Пользователей пока нет.</p>{/if}
   <div class="admin-list">{#each users as u}<article class="device-card" aria-label={u.display_name}>
    <div class="card-top"><h3>{u.display_name}</h3><span class="pill pending">{u.state==='active'?'Активен':states[u.state]}</span></div>
    <p>{u.login}</p><p>Устройств: {u.used_slots} из {u.device_limit}</p><p class="muted">{invitations[u.invitation]}{u.recovery_pending?' · Ожидает восстановления':''}</p>
   </article>{/each}</div>
   <p class="footnote">Приглашения и восстановление выдаются администратором через локальную команду. Здесь показано их состояние.</p>
  {:else}
   <h2>Журнал действий</h2>
   {#if !busy&&audit.length===0}<p class="muted">Действий пока нет.</p>{/if}
   <div class="admin-list">{#each audit as event}<article class="status-card">
    <div><h3>{actions[event.action]??'Другое действие'}</h3><p>{event.actor_kind==='trusted-cli'?'Команда администратора':event.actor_kind==='user'?'Пользователь':'Источник не определён'}</p><small>{new Date(event.time).toLocaleString('ru-RU')}</small>{#if event.object_id}<code>{event.object_id}</code>{/if}</div>
    <span class="pill" class:pending={event.outcome!=='success'}>{event.outcome==='success'?'Выполнено':event.outcome==='failed'?'Ошибка':'Результат не определён'}</span>
   </article>{/each}</div>
   <p class="footnote">Это действия кабинета и локальных команд. Журнал сетевых операций будет добавлен вместе с агентом.</p>
  {/if}
  <div class="admin-pagination"><span>Страница {page}</span><button disabled={busy||page===1} onclick={()=>load()}>Сначала</button><button disabled={busy||!cursor} onclick={()=>load(true)}>Далее</button></div>
 {/if}
</section>

<style>
 .admin-data{margin-top:24px}.admin-toolbar{display:flex;align-items:end;gap:12px;flex-wrap:wrap;margin:16px 0 24px}.admin-toolbar label{display:grid;gap:8px;font-size:12px;color:#63716b}.admin-toolbar select,.admin-toolbar button,.admin-pagination button{font:inherit;padding:10px;border:1px solid #cad6cf;background:white;border-radius:8px;max-width:100%}.admin-list{display:grid;gap:14px}.admin-list h3{margin:0;font-size:17px}.admin-list .card-top{align-items:start;flex-wrap:wrap}.admin-list p{font-size:13px;overflow-wrap:anywhere}.admin-list code{font-size:11px;overflow-wrap:anywhere;word-break:break-word}.admin-list details{margin-top:16px;font-size:12px}.admin-list summary{cursor:pointer}.admin-list dl{display:grid;gap:6px}.admin-list dd{margin:0 0 8px}.admin-list dt{color:#748178}.admin-list .status-card>div{min-width:0}.admin-pagination{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:24px;font-size:12px}.admin-pagination span{margin-right:auto}.admin-data .profile{flex-wrap:wrap}.admin-data .platforms button{font-size:12px;padding:10px 12px}select:focus-visible,summary:focus-visible{outline:3px solid #12695d;outline-offset:3px}
</style>
