<script lang="ts">
 import {api,APIError} from './api';
 let {csrf,oncomplete}:{csrf:string;oncomplete:()=>Promise<void>}=$props();
 type Mode='login'|'invite'|'recovery';
 let mode=$state<Mode>('login');let login=$state('');let token=$state('');let password=$state('');let confirm=$state('');let busy=$state(false);let error=$state('');let notice=$state('');let refreshNeeded=$state(false);let preauth=$state<string|null>(null);
 function clearSecrets(){password='';confirm='';token='';}
 function switchMode(next:Mode){mode=next;clearSecrets();error='';notice='';}
 async function refresh(){busy=true;error='';try{preauth=(await api.bootstrap()).csrf_token;refreshNeeded=false;}catch{error='Не удалось обновить форму. Проверьте соединение и повторите.';}finally{busy=false;}}
 async function submit(event:SubmitEvent){
  event.preventDefault();error='';notice='';if(mode!=='login'&&password!==confirm){error='Пароли не совпадают';return;}busy=true;
  try{
   if(mode==='recovery'){
    await api.recover({token:token.trim(),new_password:password},preauth??csrf);
    clearSecrets();mode='login';notice='Пароль обновлён. Войдите с новым паролем. Прежние сессии завершены.';
    refreshNeeded=true;preauth=(await api.bootstrap()).csrf_token;refreshNeeded=false;
   }else{
    if(mode==='invite')await api.accept({token:token.trim(),password},preauth??csrf);else await api.login({login,password},preauth??csrf);
    clearSecrets();await oncomplete();
   }
  }catch(e){error=e instanceof Error?e.message:'Не удалось выполнить действие';if(e instanceof APIError&&e.status===403)refreshNeeded=true;}finally{busy=false;}
 }
</script>
<section class="auth-panel">
 <div class="eyebrow">ЛИЧНЫЙ КАБИНЕТ</div><h1>{mode==='login'?'Вход в кабинет':mode==='invite'?'Принять приглашение':'Восстановить доступ'}</h1>
 {#if mode==='recovery'}<p>Получите одноразовый код у администратора и задайте новый пароль. Восстановление касается кабинета; VPN-профили сохраняются.</p>
 {:else}<p>Доступ только по приглашению. Пока это локальный стенд: подключение устройств и выдача VPN-профилей ещё не доступны.</p>{/if}
 <div class="platforms"><button class:active={mode==='login'} disabled={busy} onclick={()=>switchMode('login')}>Вход</button><button class:active={mode==='invite'} disabled={busy} onclick={()=>switchMode('invite')}>У меня приглашение</button></div>
 {#if notice}<p class="auth-notice" role="status">{notice}</p>{/if}
 <form onsubmit={submit}>
  {#if mode==='login'}<label for="login">Логин</label><input id="login" name="username" autocomplete="username" bind:value={login} required minlength="3" maxlength="64" disabled={busy}/>
  {:else}<label for="invite">{mode==='recovery'?'Код восстановления':'Код приглашения'}</label><input id="invite" type="password" autocomplete="off" bind:value={token} required minlength="43" maxlength="43" disabled={busy}/><p class="form-hint">Одноразовый код от администратора. Вставьте его в поле, не в адресную строку.</p>{/if}
  <label for="password">{mode==='recovery'?'Новый пароль':'Пароль'}</label><input id="password" name="password" type="password" autocomplete={mode==='login'?'current-password':'new-password'} bind:value={password} required minlength={mode==='login'?1:12} maxlength="1024" disabled={busy}/>
  {#if mode!=='login'}<p class="form-hint">Минимум 12 символов. Для стенда используйте отдельный тестовый пароль.</p><label for="confirm">Повторите пароль</label><input id="confirm" type="password" autocomplete="new-password" bind:value={confirm} required disabled={busy}/>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <button class="primary" type="submit" disabled={busy||refreshNeeded}>{busy?'Проверяем…':mode==='login'?'Войти':mode==='invite'?'Активировать кабинет':'Сохранить новый пароль'}</button>
  {#if refreshNeeded}<button type="button" class="logout" onclick={refresh} disabled={busy}>Обновить форму</button>{/if}
 </form>
 {#if mode!=='recovery'}<button class="logout" onclick={()=>switchMode('recovery')} disabled={busy}>Забыли пароль?</button>{:else}<p class="form-hint">Старый пароль и сессии отключаются при выдаче кода. Если код истёк или потерян, попросите администратора выдать новый.</p>{/if}
 <p class="form-hint auth-future">Passkey пока не доступен. Администратор входит через отдельный адрес.</p>
</section>
