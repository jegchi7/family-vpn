import {test,expect} from '@playwright/test';
import {randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdirSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=resolve(fileURLToPath(new URL('../..',import.meta.url)));
const state=process.env.FVPN_TEST_STATE;
if(!state)throw new Error('Use auth Playwright config');

test('versioned guide downloads and opens without network or personalized data',async({page,browser},info)=>{
 expect((await page.request.get('/api/v1/instructions/portal-ios/offline')).status()).toBe(401);
 const login='guide-'+randomBytes(8).toString('hex');const password=randomBytes(24).toString('base64url');
 const invite=JSON.parse(execFileSync(resolve(root,'build',process.platform==='win32'?'vpnctl.exe':'vpnctl'),['auth-invite','--root',state!,'--login',login,'--name','Проверка памятки'],{encoding:'utf8'}));
 await page.goto('/');await page.getByRole('button',{name:'У меня приглашение'}).click();await page.getByLabel('Код приглашения').fill(invite.token);await page.getByLabel('Пароль',{exact:true}).fill(password);await page.getByLabel('Повторите пароль').fill(password);await page.getByRole('button',{name:'Активировать кабинет'}).click();await expect(page.getByRole('heading',{name:'Устройств пока нет'})).toBeVisible();
 await page.getByRole('button',{name:'Как подключиться',exact:true}).click();
 const entries=(await(await page.request.get('/api/v1/instructions')).json()).items;
 expect(entries.filter((g:any)=>g.kind==='vpn').every((g:any)=>!g.verified&&g.verification_scope==='none')).toBe(true);
 for(const [os,label] of [['ios','iPhone / iPad'],['android','Android'],['windows','Windows'],['macos','macOS'],['linux','Linux'],['other','Другое']]){
  await page.getByRole('button',{name:label,exact:true}).click();const guide=entries.find((g:any)=>g.os===os&&g.kind==='portal');await expect(page.getByRole('article',{name:guide.title,exact:true})).toContainText('Проверен сценарий кабинета');expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 }
 await page.getByRole('button',{name:'iPhone / iPad',exact:true}).click();
 const guide=entries.find((g:any)=>g.id==='portal-ios');const card=page.getByRole('article',{name:guide.title,exact:true});
 const downloadEvent=page.waitForEvent('download');await card.getByRole('link',{name:'Скачать офлайн-памятку ↓'}).click();const download=await downloadEvent;
 expect(download.suggestedFilename()).toBe('family-vpn-guide-portal-ios-v1.html');
 const dir=`${state}-offline/${info.project.name}`;mkdirSync(dir,{recursive:true,mode:0o700});const file=resolve(dir,'guide.html');await download.saveAs(file);const contents=readFileSync(file,'utf8');
 const cookies=await page.context().cookies();expect(!contents.includes(invite.token)&&!contents.includes(password)&&!contents.includes(login)&&cookies.every(c=>!contents.includes(c.value))).toBe(true);
 const response=await page.request.get('/api/v1/instructions/portal-ios/offline');expect(response.headers()['content-type']).toBe('text/html; charset=utf-8');expect(response.headers()['cache-control']).toBe('no-store');expect(response.headers()['referrer-policy']).toBe('no-referrer');
 expect((await page.request.get('/api/v1/instructions/missing/offline')).status()).toBe(404);expect((await page.request.get('/api/v1/instructions/portal-ios/offline?token=unexpected')).status()).toBe(400);
 const offlineContext=await browser.newContext({offline:true,viewport:info.project.use.viewport});const offlinePage=await offlineContext.newPage();const external:string[]=[];offlinePage.on('request',r=>{if(/^https?:/.test(r.url()))external.push(r.url())});
 try{
  await offlinePage.goto(pathToFileURL(file).href);await expect(offlinePage.getByRole('heading',{name:guide.title})).toBeVisible();await expect(offlinePage.locator('li')).toHaveCount(guide.steps.length);expect(external).toHaveLength(0);expect(await offlinePage.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  if(process.env.FVPN_CAPTURE_DIR){mkdirSync(process.env.FVPN_CAPTURE_DIR,{recursive:true});await page.screenshot({path:resolve(process.env.FVPN_CAPTURE_DIR,`guides-${info.project.name}.png`),fullPage:true});await offlinePage.screenshot({path:resolve(process.env.FVPN_CAPTURE_DIR,`guide-offline-${info.project.name}.png`),fullPage:true});}
 }finally{await offlineContext.close()}
});
