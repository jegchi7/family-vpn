<script lang="ts">
 import {api} from './api';
 let {csrf,oncomplete}:{csrf:string;oncomplete:()=>Promise<void>}=$props();
 let login=$state('');let password=$state('');let code=$state('');let challenge=$state('');let expires=$state('');let error=$state('');let busy=$state(false);let preauth=$state<string|null>(null);
 async function restart(){busy=true;error='';password='';code='';challenge='';try{preauth=(await api.bootstrap()).csrf_token;}catch{error='Не удалось обновить форму. Повторите попытку.';}finally{busy=false;}}
 async function submit(event:SubmitEvent){
  event.preventDefault();busy=true;error='';
  try{
   if(!challenge){const c=await api.adminPassword({login,password},preauth??csrf);password='';challenge=c.challenge;expires=c.expires_at;}
   else{await api.adminTOTP({challenge,code},preauth??csrf);code='';challenge='';await oncomplete();}
  }catch{error=challenge?'Код не принят, запрос истёк или достигнут лимит попыток. Проверьте часы и используйте новый код; при необходимости начните вход заново.':'Вход не выполнен. Проверьте данные и завершение настройки TOTP. После нескольких попыток подождите 5 минут.';}
  finally{password='';code='';busy=false;}
 }
</script>
<section class="auth-panel">
 <div class="eyebrow">АДМИНИСТРИРОВАНИЕ</div><h1>{challenge?'Подтвердите вход':'Вход администратора'}</h1>
 <p>{challenge?'Введите шестизначный код из приложения-аутентификатора. Пароль проверен; сессия ещё не создана.':'Для входа нужны пароль и код TOTP. Первичная настройка выполняется через локальную консоль.'}</p>
 <form onsubmit={submit}>
  {#if challenge}
   <label for="admin-code">Код аутентификатора</label><input id="admin-code" type="password" inputmode="numeric" autocomplete="one-time-code" minlength="6" maxlength="6" pattern={'[0-9]{6}'} bind:value={code} required disabled={busy}/>
   <p class="form-hint">Запрос действует до {new Date(expires).toLocaleTimeString('ru-RU')}. Использованный код повторно не принимается.</p>
  {:else}
   <label for="admin-login">Логин администратора</label><input id="admin-login" autocomplete="username" bind:value={login} required minlength="3" maxlength="64" disabled={busy}/>
   <label for="admin-password">Пароль</label><input id="admin-password" type="password" autocomplete="current-password" bind:value={password} required maxlength="1024" disabled={busy}/>
  {/if}
  {#if error}<p role="alert" class="error">{error}</p>{/if}
  <button type="submit" class="primary" disabled={busy}>{busy?'Проверяем…':challenge?'Подтвердить вход':'Продолжить'}</button>
 </form>
 <button class="logout" onclick={restart} disabled={busy}>{challenge?'Начать вход заново':'Обновить форму'}</button>
 <p class="form-hint">Если аутентификатор потерян, используйте процедуру admin-reset через доверенную консоль. Восстановление пользовательского пароля здесь не действует.</p>
</section>
