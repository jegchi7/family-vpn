import {test,expect,request} from '@playwright/test';
import {randomBytes,createHmac,randomUUID,generateKeyPairSync} from 'node:crypto';
import {execFileSync,spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {mkdirSync,existsSync} from 'node:fs';
const root=resolve(fileURLToPath(new URL('../..',import.meta.url)));
const ctlPath=resolve(root,'build',process.platform==='win32'?'vpnctl.exe':'vpnctl');
const portalPath=resolve(root,'build',process.platform==='win32'?'portal.exe':'portal');
const state=process.env.FVPN_ADMIN_TEST_STATE;
if(!state)throw new Error('Use playwright.admin.config.ts');
// Independent RFC 6238 fixture generator, test-only; application uses pquerna/otp.
function otp(secret:string,step:number){
 const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const c of secret)bits+=alphabet.indexOf(c).toString(2).padStart(5,'0');
 const key=Buffer.from((bits.match(/.{8}/g)??[]).map(b=>parseInt(b,2)));const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(step));const h=createHmac('sha1',key).update(counter).digest();const o=h[h.length-1]&15;return ((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0');
}
test('CLI enrollment → password → TOTP → isolated admin session → disable',async({page},testInfo)=>{
 test.setTimeout(60000);
 async function capture(name:string){if(process.env.FVPN_CAPTURE_DIR){mkdirSync(process.env.FVPN_CAPTURE_DIR,{recursive:true});await page.screenshot({path:resolve(process.env.FVPN_CAPTURE_DIR,`admin-${name}-${testInfo.project.name}.png`),fullPage:true});}}
 const login='admin-'+randomBytes(8).toString('hex');const password=randomBytes(24).toString('base64url');
 function ctl(command:string,input?:unknown){return execFileSync(ctlPath,[command,'--root',state!,'--master-key',`${state}-secrets/master.key`,'--login',login],{encoding:'utf8',input:input===undefined?undefined:JSON.stringify(input),stdio:['pipe','pipe','pipe']});}
 const setup=JSON.parse(ctl('admin-enroll',{password}));
 // Confirm previous accepted step, then use the current step for login. Avoid sleeping for a TOTP rotation.
 let step=Math.floor(Date.now()/30000);ctl('admin-confirm',{code:otp(setup.secret,step-1)});
 await page.goto('/');await expect(page.getByRole('heading',{name:'Вход администратора'})).toBeVisible();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await capture('login');
 await page.getByLabel('Логин администратора').fill(login);await page.getByLabel('Пароль',{exact:true}).fill(password);await page.getByRole('button',{name:'Продолжить',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Подтвердите вход'})).toBeVisible();
 expect((await page.request.get('/api/v1/admin/overview')).status()).toBe(401);
 expect((await page.context().cookies()).some(c=>c.name==='__Host-fvpn_admin_session')).toBe(false);await capture('totp');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.getByLabel('Код аутентификатора').fill(otp(setup.secret,Math.floor(Date.now()/30000)));await page.getByRole('button',{name:'Подтвердить вход',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Отдельный контур.'})).toBeVisible();await capture('overview');
 const userRoot=`${state}/users`;const portal=spawn(portalPath,['--local-auth','--listen','127.0.0.1:8444','--portal-db',`${userRoot}/portal/state.db`,'--tls-cert',`${userRoot}/tls/local-cert.pem`,'--tls-key',`${userRoot}/tls/local-key.pem`,'--web-dir',resolve(root,'web/dist')],{stdio:'ignore'});
 const user=await request.newContext({baseURL:'https://127.0.0.1:8444',ignoreHTTPSErrors:true});
 try{
  await expect.poll(async()=>{try{return(await user.get('/healthz')).status()}catch{return 503}},{timeout:10000}).toBe(200);
  const userLogin='view-'+randomBytes(8).toString('hex');
  const userInvite=JSON.parse(execFileSync(ctlPath,['auth-invite','--root',userRoot,'--login',userLogin,'--name',`Семейный пользователь ${testInfo.project.name}`],{encoding:'utf8'}));
  const userBootstrap=await(await user.get('/api/v1/auth/bootstrap')).json();
  expect((await user.post('/api/v1/auth/invitations/accept',{headers:{'Origin':'https://127.0.0.1:8444','X-CSRF-Token':userBootstrap.csrf_token},data:{token:userInvite.token,password:randomBytes(24).toString('base64url')}})).status()).toBe(200);
  const me=await(await user.get('/api/v1/me')).json();
  const deviceName=`Телефон для настройки ${testInfo.project.name}`;const created=await user.post('/api/v1/devices',{headers:{'Origin':'https://127.0.0.1:8444','X-CSRF-Token':me.csrf_token},data:{request_id:randomUUID(),name:deviceName,os:'ios'}});expect(created.status()).toBe(200);const device=await created.json();
  const cancelledRequest=await user.post('/api/v1/devices',{headers:{'Origin':'https://127.0.0.1:8444','X-CSRF-Token':me.csrf_token},data:{request_id:randomUUID(),name:`Отменяемая заявка ${testInfo.project.name}`,os:'ios'}});expect(cancelledRequest.status()).toBe(200);const cancelled=await cancelledRequest.json();
  expect((await user.post(`/api/v1/devices/${cancelled.id}/cancel`,{headers:{'Origin':'https://127.0.0.1:8444','X-CSRF-Token':me.csrf_token},data:{expected_revision:cancelled.revision}})).status()).toBe(200);
  const key=`${state}-profile-secrets/current.key`;if(!existsSync(key))execFileSync(ctlPath,['profile-key-create','--root',userRoot,'--profile-key',key]);execFileSync(ctlPath,['profile-vault-init','--root',userRoot,'--profile-key',key]);
  const target=JSON.parse(execFileSync(ctlPath,['profile-targets','--root',userRoot,'--login',userLogin,'--device-id',device.id],{encoding:'utf8'})).targets.find((p:any)=>p.protocol==='reality');
  const uuid=randomUUID();const pair=generateKeyPairSync('x25519');const pbk=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64url');
  const uri=`vless://${uuid}@edge.example.invalid:443?type=tcp&security=reality&flow=xtls-rprx-vision&fp=chrome&sni=cover.example.invalid&pbk=${pbk}&sid=00#Test`;
  execFileSync(ctlPath,['profile-import','--root',userRoot,'--profile-key',key,'--owner-id',target.owner_id,'--device-id',target.device_id,'--profile-id',target.profile_id,'--generation','1','--expected-revision','1','--format','vless-reality-uri','--apply'],{input:uri,encoding:'utf8'});
  const waiting=JSON.parse(execFileSync(ctlPath,['auth-invite','--root',userRoot,'--login','waiting-'+randomBytes(8).toString('hex'),'--name',`Ожидающий пользователь ${testInfo.project.name}`],{encoding:'utf8'}));
  await page.getByRole('button',{name:'Обновить список',exact:true}).click();
  const card=page.getByRole('article',{name:deviceName,exact:true});await expect(card).toContainText('Сохранён, ждёт сверки');await expect(card).toContainText('Ждёт импорта');
  await expect(card.getByRole('link')).toHaveCount(0);await expect(page.getByRole('button',{name:'Обновить список',exact:true})).toBeEnabled();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await capture('queue');
  await page.getByRole('button',{name:'Пользователи',exact:true}).click();await expect(page.getByRole('article',{name:`Семейный пользователь ${testInfo.project.name}`,exact:true})).toContainText('Устройств: 1 из 5');await expect(page.getByRole('article',{name:`Ожидающий пользователь ${testInfo.project.name}`,exact:true})).toContainText('Приглашение действует');await capture('users');
  function recoveryToken(){return JSON.parse(execFileSync(ctlPath,['auth-recovery','--root',userRoot,'--login',userLogin],{encoding:'utf8'})).token as string;}
  const revokedRecovery=recoveryToken();const currentRecovery=recoveryToken();
  expect((await user.get('/api/v1/me')).status()).toBe(401);
  await page.getByRole('button',{name:'Обновить список',exact:true}).click();const userCard=page.getByRole('article',{name:`Семейный пользователь ${testInfo.project.name}`,exact:true});await expect(userCard).toContainText('Ожидает восстановления');
  const recoveryBootstrap=await(await user.get('/api/v1/auth/bootstrap')).json();
  expect((await user.post('/api/v1/auth/recovery/consume',{headers:{'Origin':'https://127.0.0.1:8444','X-CSRF-Token':recoveryBootstrap.csrf_token},data:{token:currentRecovery,new_password:randomBytes(24).toString('base64url')}})).status()).toBe(204);
  expect((await user.get('/api/v1/me')).status()).toBe(401);
  await page.getByRole('button',{name:'Обновить список',exact:true}).click();await expect(userCard).not.toContainText('Ожидает восстановления');await expect(userCard).toContainText('Устройств: 1 из 5');
  const userView=await(await page.request.get('/api/v1/admin/users?limit=100')).json();expect(userView.items.find((u:any)=>u.id===me.id)?.recovery_pending).toBe(false);
  await page.getByRole('button',{name:'Журнал действий',exact:true}).click();await expect(page.getByRole('heading',{name:'Конфиг сохранён'}).first()).toBeVisible();
  const cancelEvent=page.getByRole('article').filter({has:page.getByRole('heading',{name:'Заявка отменена',exact:true})}).filter({hasText:cancelled.id});await expect(cancelEvent).toContainText('Выполнено');await expect(cancelEvent.getByText(cancelled.id,{exact:true})).toBeVisible();await capture('audit');
  const auditView=await(await page.request.get('/api/v1/admin/audit?limit=100')).json();expect(auditView.items.filter((a:any)=>a.action==='device.cancel'&&a.object_id===cancelled.id)).toHaveLength(1);
  for(const route of ['users','devices','audit']){
   const res=await page.request.get(`/api/v1/admin/${route}`);expect(res.status()).toBe(200);const raw=await res.text();expect(!raw.includes(uri)&&!raw.includes(uuid)&&!raw.includes(pbk)&&!raw.includes(waiting.token)&&!raw.includes(userInvite.token)&&!raw.includes(revokedRecovery)&&!raw.includes(currentRecovery)).toBe(true);
   expect(res.headers()['cache-control']).toBe('no-store');expect(res.headers()['referrer-policy']).toBe('no-referrer');
   const adminCookie=(await page.context().cookies()).find(c=>c.name==='__Host-fvpn_admin_session');expect((await user.get(`/api/v1/admin/${route}`,{headers:{Cookie:`__Host-fvpn_admin_session=${adminCookie!.value}`}})).status()).toBe(404);
  }
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 }finally{await user.dispose();portal.kill('SIGTERM');await new Promise<void>(done=>{if(portal.exitCode!==null)done();else portal.once('exit',()=>done());});}

 const cookie=(await page.context().cookies()).find(c=>c.name==='__Host-fvpn_admin_session');expect(!!cookie?.httpOnly&&!!cookie?.secure&&cookie?.sameSite==='Strict').toBe(true);
 expect(await page.evaluate(()=>localStorage.length)).toBe(0);
 await page.reload();await expect(page.getByRole('heading',{name:'Отдельный контур.'})).toBeVisible();
 await page.getByRole('button',{name:'Выйти',exact:true}).click();await expect(page.getByRole('heading',{name:'Вход администратора'})).toBeVisible();
 await page.getByLabel('Логин администратора').fill(login);await page.getByLabel('Пароль',{exact:true}).fill(password);await page.getByRole('button',{name:'Продолжить',exact:true}).click();await expect(page.getByRole('heading',{name:'Подтвердите вход'})).toBeVisible();
 ctl('admin-disable');await page.getByLabel('Код аутентификатора').fill(otp(setup.secret,Math.floor(Date.now()/30000)));await page.getByRole('button',{name:'Подтвердить вход',exact:true}).click();await expect(page.getByRole('alert')).toContainText('Код не принят');
 expect((await page.request.get('/api/v1/admin/overview')).status()).toBe(401);
 await page.getByRole('button',{name:'Начать вход заново'}).click();await expect(page.getByRole('heading',{name:'Вход администратора'})).toBeVisible();
});
