import {test,expect} from '@playwright/test';
import {randomBytes,randomUUID,generateKeyPairSync,createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {existsSync,mkdirSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
const root=resolve(fileURLToPath(new URL('../..',import.meta.url)));
const state=process.env.FVPN_TEST_STATE;
if(!state)throw new Error('Use auth Playwright config');
for (const format of ['vless-reality-uri','awg-3.1-conf']) {
test(`${format}: CLI import stays pending and never exposes client secrets in portal`,async({page},info)=>{
 const ctl=resolve(root,'build',process.platform==='win32'?'vpnctl.exe':'vpnctl');
 const login='import-'+randomBytes(8).toString('hex');const password=randomBytes(24).toString('base64url');
 const invite=JSON.parse(execFileSync(ctl,['auth-invite','--root',state!,'--login',login,'--name','Проверка импорта'],{encoding:'utf8'}));
 await page.goto('/');await page.getByRole('button',{name:'У меня приглашение'}).click();await page.getByLabel('Код приглашения').fill(invite.token);await page.getByLabel('Пароль',{exact:true}).fill(password);await page.getByLabel('Повторите пароль').fill(password);await page.getByRole('button',{name:'Активировать кабинет'}).click();await expect(page.getByRole('heading',{name:'Устройств пока нет'})).toBeVisible();
 const me=await(await page.request.get('/api/v1/me')).json();const headers={'Origin':'https://127.0.0.1:8443','X-CSRF-Token':me.csrf_token};
 const created=await page.request.post('/api/v1/devices',{headers,data:{request_id:randomUUID(),name:'Телефон с конфигом',os:'ios'}});expect(created.status()).toBe(200);const device=await created.json();
 const targets=JSON.parse(execFileSync(ctl,['profile-targets','--root',state!,'--login',login,'--device-id',device.id],{encoding:'utf8'}));const target=targets.targets.find((p:any)=>p.protocol===(format==='awg-3.1-conf'?'awg':'reality'));
 const key=`${state}-profile-secrets/current.key`;
 if(!existsSync(key))execFileSync(ctl,['profile-key-create','--root',state!,'--profile-key',key]);
 execFileSync(ctl,['profile-vault-init','--root',state!,'--profile-key',key]);
 const uuid=randomUUID();const pair=generateKeyPairSync('x25519');const pbk=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64url');
 let uri=`vless://${uuid}@edge.example.invalid:443?type=tcp&security=reality&flow=xtls-rprx-vision&fp=chrome&sni=cover.example.invalid&pbk=${pbk}&sid=00#Test\n`;
 const awgPrivate=pair.privateKey.export({format:'der',type:'pkcs8'}).subarray(-32).toString('base64');
 const awgHeader=randomBytes(32).toString('base64');
 if(format==='awg-3.1-conf') {
  const server=generateKeyPairSync('x25519').publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
  uri=`[Interface]\r\nPrivateKey = ${awgPrivate}\r\nAddress = 10.77.0.2/32\r\nDNS = 10.77.0.1\r\nJc = 3\r\nJmin = 40\r\nJmax = 70\r\nS1 = 16\r\nS2 = 16\r\nS3 = 16\r\nS4 = 16\r\nH1 = 1\r\nH2 = 2\r\nH3 = 3\r\nH4 = 4\r\nHeaderProtectionKey = ${awgHeader}\r\nRandomTrailers = on\r\nDisableCookies = off\r\nContentPaddingAddition = 0-64\r\n[Peer]\r\nPublicKey = ${server}\r\nEndpoint = edge.example.invalid:443\r\nAllowedIPs = 0.0.0.0/0\r\nPersistentKeepalive = 20-30\r\n`;
 }
 const args=['profile-import','--root',state!,'--profile-key',key,'--owner-id',target.owner_id,'--device-id',target.device_id,'--profile-id',target.profile_id,'--generation',String(target.generation),'--expected-revision',String(target.device_revision),'--format',format];
 const run=(extra:string[])=>JSON.parse(execFileSync(ctl,[...args,...extra],{input:uri,encoding:'utf8'}));
 expect(run([]).outcome).toBe('would-import');expect(run(['--apply']).outcome).toBe('imported-pending');expect(run(['--apply']).outcome).toBe('already-stored');
 await page.reload();const card=page.getByRole('article',{name:'Телефон с конфигом',exact:true});await expect(card).toContainText('Сохранён, ждёт сверки');await expect(card).toContainText('ещё не подтвердил');await expect(card.getByRole('button',{name:'Отменить заявку'})).toHaveCount(0);await expect(card.getByRole('link')).toHaveCount(0);
 const metadataResponse=await page.request.get('/api/v1/devices');const metadata=await metadataResponse.text();expect(!metadata.includes(uuid)&&!metadata.includes(pbk)&&!metadata.includes(uri)).toBe(true);
 const storedDevice=JSON.parse(metadata).items.find((d:any)=>d.id===device.id);expect(storedDevice.state).toBe('pending');expect(storedDevice.profiles.find((p:any)=>p.id===target.profile_id)).toMatchObject({format,state:'pending'});
 if(format==='vless-reality-uri') {
 const privateKey=pair.privateKey.export({format:'der',type:'pkcs8'}).subarray(-32).toString('base64url');
 const snapshot=JSON.stringify({inbounds:[{tag:'clients',listen:'0.0.0.0',port:443,protocol:'vless',settings:{decryption:'none',clients:[{id:uuid,flow:'xtls-rprx-vision'}]},streamSettings:{network:'raw',security:'reality',realitySettings:{privateKey,serverNames:['cover.example.invalid'],shortIds:['00'],target:'cover.example.invalid:443'}}}]});
 const pin=createHash('sha256').update(snapshot).digest('hex');
 const preflightArgs=['profile-preflight','--root',state!,'--profile-key',key,'--owner-id',target.owner_id,'--device-id',target.device_id,'--profile-id',target.profile_id,'--generation',String(target.generation),'--expected-revision','2','--inbound-tag','clients','--expected-endpoint','edge.example.invalid:443','--expected-config-sha256',pin];
 const reportText=execFileSync(ctl,preflightArgs,{input:snapshot,encoding:'utf8'});
 const report=JSON.parse(reportText);expect(report.configuration_matches).toBe(true);expect(report.ready).toBe(false);expect(report.runtime_verified).toBe(false);expect(report.clients_verified).toBe(false);
 expect(!reportText.includes(uuid)&&!reportText.includes(pbk)&&!reportText.includes(privateKey)).toBe(true);
 expect(await(await page.request.get('/api/v1/devices')).text()).toBe(metadata);
 }
 expect(!metadata.includes(awgPrivate)&&!metadata.includes(awgHeader)).toBe(true);
 const body=await page.locator('body').innerText();expect(!body.includes(uuid)&&!body.includes(pbk)&&!body.includes(awgPrivate)&&!body.includes(awgHeader)).toBe(true);
 expect((await page.request.get(`/api/v1/profiles/${target.profile_id}/download`)).status()).toBe(409);
 expect((await page.request.post(`/api/v1/devices/${device.id}/cancel`,{headers,data:{expected_revision:2}})).status()).toBe(409);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 if(process.env.FVPN_CAPTURE_DIR){mkdirSync(process.env.FVPN_CAPTURE_DIR,{recursive:true});await page.screenshot({path:resolve(process.env.FVPN_CAPTURE_DIR,`import-pending-${format}-${info.project.name}.png`),fullPage:true});}
});
}
