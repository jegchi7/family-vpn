<script lang="ts">
 import { onMount } from 'svelte';
 import {version as appVersion} from '../package.json';
 import AuthForm from './lib/AuthForm.svelte';
 import DeviceManager from './lib/DeviceManager.svelte';
 import AdminAuthForm from './lib/AdminAuthForm.svelte';
 import AdminDashboard from './lib/AdminDashboard.svelte';
 import GuideList from './lib/GuideList.svelte';
 import { api, APIError, type Device, type Health, type Instruction, type Me, type Overview } from './lib/api';
 let tab = $state('devices');
 let adminAuth=$state(false);let authRequired=$state(false);let csrf=$state('');let localAuth=$state(false);
 let devices = $state<Device[]>([]); let health = $state<Health[]>([]); let guides = $state<Instruction[]>([]);
 let me = $state<Me | null>(null); let overview = $state<Overview | null>(null);
 let loading = $state(true); let error = $state(''); let now = $state(Date.now());
 const labels: Record<string,string> = { healthy: 'Работает · демо', degraded: 'Резерв · демо', unknown: 'Неизвестно', unavailable: 'Недоступно' };
 async function load() {
  loading = true; error = '';
  try {
   const m=await api.me();me=m;authRequired=false;localAuth=m.mode!=='demo';adminAuth=m.mode==='local-admin';csrf=m.csrf_token??'';
   const [d,h,g]=await Promise.all([api.devices(),api.status(),api.instructions()]);devices=d.items;health=h.items;guides=g.items;
   if(m.role==='admin') { overview=await api.overview();tab='admin'; }
   if(localAuth)await api.touch(csrf);
  } catch(e) {
   if(e instanceof APIError&&e.status===401){me=null;devices=[];health=[];guides=[];overview=null;csrf='';
    try{const b=await api.bootstrap();csrf=b.csrf_token;adminAuth=b.mode==='local-admin';localAuth=true;authRequired=true;tab='devices';}catch{error='Не удалось открыть форму входа. Повторите загрузку.';}
   }else{error=e instanceof Error?e.message:'Не удалось загрузить данные';}
  }
  finally {loading=false;}
 }
 async function logout(){try{await api.logout(csrf);me=null;devices=[];health=[];guides=[];overview=null;csrf='';await load();}catch(e){error=e instanceof Error?e.message:'Не удалось завершить сессию';}}
 function status(h: Health) { return now>=Date.parse(h.expires_at)?'unknown':h.status; }
 onMount(() => {
  // Tokens are pasted into a form. Remove accidental fragment without retaining it.
  if(location.hash)history.replaceState(null,'',location.pathname+location.search);
  void load();const timer=setInterval(()=>{now=Date.now();},1000);
  const activity=setInterval(()=>{if(localAuth&&me&&document.visibilityState==='visible')void api.touch(csrf).catch(()=>load());},300000);
  return()=>{clearInterval(timer);clearInterval(activity);};
 });
</script>

<svelte:head><title>{me?.role==='admin'?'Управление':'Мой доступ'} · Семейный VPN</title></svelte:head>
<div class="app-shell">
 <aside>
  <a class="brand" href="/" aria-label="Семейный VPN — главная"><span class="brand-mark">↗</span><span>Семейный VPN<small>Личный кабинет</small></span></a>
  {#if me}<nav aria-label="Разделы">
   <button class:active={tab==='devices'} onclick={()=>tab='devices'}>Мои устройства <span>{devices.length}</span></button>
   <button class:active={tab==='guides'} onclick={()=>tab='guides'}>Как подключиться</button>
   <button class:active={tab==='status'} onclick={()=>tab='status'}>Проверка связи</button>
   {#if me?.role==='admin'}<button class:active={tab==='admin'} onclick={()=>tab='admin'}>Администрирование</button>{/if}
  </nav>{/if}
  <div class="side-note"><strong>Всегда под рукой</strong><p>Сохраните основной и резервный профили заранее. В рабочей системе кабинет не нужен для самого подключения.</p></div>
  <div class="identity"><span class="avatar">{me?.role==='admin'?'А':'С'}</span><div>{me?.display_name ?? (authRequired?'Войдите в кабинет':'Загрузка…')}<small>Локальный стенд · SQLite</small></div></div>
 {#if localAuth && me}<button class="logout" onclick={logout}>Выйти</button>{/if}
 </aside>
 <main>
  <div class="demo-banner"><span class="dot"></span><strong>{localAuth?'Локальный стенд авторизации':'Демонстрационный режим'}</strong><span>{localAuth?'Вход работает. VPN-серверы ещё не подключены.':'Тестовые данные. Настоящие серверы не подключены.'}</span></div>
  {#if loading}<p role="status" class="loading">Загружаем кабинет…</p>{/if}
  {#if error}<div class="error" role="alert"><p>{error}</p><button onclick={load}>Повторить загрузку</button></div>{/if}
  {#if !loading && !error}
   {#if authRequired}{#if adminAuth}<AdminAuthForm {csrf} oncomplete={load}/>{:else}<AuthForm {csrf} oncomplete={load}/>{/if}{:else if tab==='devices'}
    <header><div class="eyebrow">ВАШ ДОСТУП</div><h1>Всё для подключения.</h1><p>Профили для ваших устройств и короткие инструкции в одном месте.</p></header>
    {#if !localAuth}<section class="intro"><div><span class="tag">ПЕРВЫЙ ШАГ</span><h2>Настройте основной и резервный вход</h2><p>Если один способ перестанет работать, второй уже будет установлен.</p></div><button class="primary" onclick={()=>tab='guides'}>Как подключиться <span>↗</span></button></section>{/if}
    {#if localAuth && !adminAuth}<DeviceManager {devices} {csrf} onchange={(items)=>devices=items}/>{:else}
    <div class="section-title"><h2>Мои устройства</h2><span>{devices.length} устройства</span></div>
    {#if devices.length===0}<section class="guide"><h2>Устройств пока нет</h2><p>Вы вошли в свой кабинет. Добавление устройств и выдача конфигов будут подключены на следующем этапе.</p></section>{/if}
    <div class="device-grid">
     {#each devices as device}
      <article class="device-card"><div class="card-top"><span class="device-icon">{device.os==='ios'?'▯':'▱'}</span><span class:pending={device.state==='partial'} class="pill">{device.state==='partial'?'Профиль готовится':'Профили готовы · демо'}</span></div>
       <h3>{device.name}</h3><p class="muted">{device.os==='ios'?'iOS':'Windows'} · отдельный доступ</p>
       <div class="profiles">{#each device.profiles as profile}<div class="profile"><div><strong>{profile.protocol==='awg'?'Основной':'Резервный'}</strong><small>{profile.protocol==='awg'?'AmneziaWG':'REALITY'}</small></div>{#if profile.state==='ready'}<a class="download" href={`/api/v1/profiles/${profile.id}/download?format=txt`} download>Демо-файл ↓</a>{:else}<span class="muted">Ожидает</span>{/if}</div>{/each}</div>
       <p class="card-note">{device.state==='partial'?'Демонстрация незавершённой выдачи.':'Готовность профиля не означает, что устройство сейчас подключено.'}</p>
      </article>
     {/each}
    </div>
    {#if !localAuth}<p class="footnote">Демо-файл — обычная текстовая памятка без адресов и ключей. Его нельзя импортировать в VPN-клиент.</p>{/if}
    {/if}
   {:else if tab==='guides'}
    <GuideList {guides}/>
   {:else if tab==='status'}
    <header><div class="eyebrow">ДИАГНОСТИКА</div><h1>Что с соединением?</h1><p>Доступность сервиса и маршрут вашего браузера — разные проверки.</p></header>
    <div class="status-list">{#each health as sample}<article class="status-card"><div><h2>{sample.component}</h2><p>{now>=Date.parse(sample.expires_at)?'Результат устарел. Новое измерение не получено.':sample.reason}</p><small>Измерение: {new Date(sample.measured_at).toLocaleTimeString('ru-RU')}</small></div><span class="pill" class:pending={status(sample)!=='healthy'}>{labels[status(sample)]}</span></article>{/each}</div>
    <div class="callout"><h3>Здесь пока нет проверки вашего VPN</h3><p>{localAuth?'Сборщик измерений ещё не подключён.':'Статусы получены из тестовых данных и устаревают через 60 секунд.'} Обновление страницы не создаёт новое измерение. После подключения внешнего probe кабинет сможет проверить путь одного браузерного запроса.</p></div>
   {:else if tab==='admin' && overview}
    <header><div class="eyebrow">УПРАВЛЕНИЕ</div><h1>Отдельный контур.</h1><p>{adminAuth?'Вход защищён паролем и TOTP. Сессия действует до 12 часов, с завершением после 30 минут без активности.':'Это демонстрационный экран без аутентификации.'}</p></header>
    <section class="intro"><div><span class="tag">READ ONLY</span><h2>Устройств {adminAuth?'в локальной базе':'в тестовом наборе'}: {overview.total_devices}</h2><p>{overview.message}</p></div></section>
    {#if adminAuth}<AdminDashboard onrefresh={async()=>{overview=await api.overview();}}/>{/if}
    <article class="guide"><h2>Компоненты</h2><ul>{#each overview.components as component}<li>{component}</li>{/each}</ul></article>
   {/if}
  {/if}
  <footer>Семейный VPN <span>v{appVersion} · локальный стенд</span></footer>
 </main>
</div>
