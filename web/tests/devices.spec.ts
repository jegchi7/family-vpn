import {test,expect} from '@playwright/test';
import {randomBytes,randomUUID} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdirSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
const root=resolve(fileURLToPath(new URL('../..',import.meta.url)));
const state=process.env.FVPN_TEST_STATE;
if(!state)throw new Error('Use auth Playwright config');
test('request device → reload → revision conflict → rename → cancel → limit',async({page},info)=>{
 const login='devices-'+randomBytes(8).toString('hex');const password=randomBytes(24).toString('base64url');
 const invitation=JSON.parse(execFileSync(resolve(root,'build',process.platform==='win32'?'vpnctl.exe':'vpnctl'),['auth-invite','--root',state!,'--login',login,'--name','Проверка устройств'],{encoding:'utf8'}));
 async function capture(name:string){if(process.env.FVPN_CAPTURE_DIR){mkdirSync(process.env.FVPN_CAPTURE_DIR,{recursive:true});await page.screenshot({path:resolve(process.env.FVPN_CAPTURE_DIR,`devices-${name}-${info.project.name}.png`),fullPage:true});}}
 await page.goto('/');await page.getByRole('button',{name:'У меня приглашение'}).click();await page.getByLabel('Код приглашения').fill(invitation.token);await page.getByLabel('Пароль',{exact:true}).fill(password);await page.getByLabel('Повторите пароль').fill(password);await page.getByRole('button',{name:'Активировать кабинет'}).click();await expect(page.getByRole('heading',{name:'Устройств пока нет'})).toBeVisible();
 await page.getByRole('button',{name:'Добавить устройство'}).click();await expect(page.getByRole('heading',{name:'Новое устройство'})).toBeVisible();await capture('form');
 await page.getByLabel('Название устройства').fill('Мой телефон');await page.getByLabel('Операционная система').selectOption('android');await page.getByRole('button',{name:'Сохранить заявку'}).click();
 const card=page.getByRole('article',{name:'Мой телефон',exact:true});await expect(card).toContainText('Ожидает настройки');await expect(card).toContainText('AmneziaWG');await expect(card).toContainText('REALITY');await expect(card.getByRole('link')).toHaveCount(0);await capture('pending');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.reload();await expect(card).toBeVisible();
 const me=await (await page.request.get('/api/v1/me')).json();const headers={'Origin':'https://127.0.0.1:8443','X-CSRF-Token':me.csrf_token};let all=await(await page.request.get('/api/v1/devices')).json();const device=all.items[0];
 // Another tab changes the record after the form captured its revision.
 await card.getByRole('button',{name:'Переименовать'}).click();expect((await page.request.post(`/api/v1/devices/${device.id}/rename`,{headers,data:{name:'Из другой вкладки',expected_revision:device.revision}})).status()).toBe(200);
 await card.getByLabel('Новое название').fill('Мой Android');await card.getByRole('button',{name:'Сохранить название'}).click();await expect(page.getByRole('alert')).toContainText('Обновите список');
 await page.getByRole('button',{name:'Обновить список'}).click();await expect(page.getByRole('heading',{name:'Из другой вкладки',exact:true})).toBeVisible();
 // Refresh closes stale edits; opening again uses the current revision.
 const updated=page.getByRole('article',{name:'Из другой вкладки',exact:true});await updated.getByRole('button',{name:'Переименовать'}).click();await updated.getByLabel('Новое название').fill('Мой Android');await updated.getByRole('button',{name:'Сохранить название'}).click();
 const renamed=page.getByRole('article',{name:'Мой Android',exact:true});await expect(renamed).toBeVisible();await renamed.getByRole('button',{name:'Отменить заявку'}).click();await renamed.getByRole('button',{name:'Да, отменить'}).click();await expect(renamed).toContainText('Запись закрыта');await expect(page.getByText('Занято 0 из 5')).toBeVisible();
 for(let i=0;i<5;i++)expect((await page.request.post('/api/v1/devices',{headers,data:{request_id:randomUUID(),name:`Тест ${i+1}`,os:'ios'}})).status()).toBe(200);
 const overflow=await page.request.post('/api/v1/devices',{headers,data:{request_id:randomUUID(),name:'Лишнее',os:'ios'}});expect(overflow.status()).toBe(409);
 await page.reload();await expect(page.getByText('Занято 5 из 5')).toBeVisible();await expect(page.getByRole('button',{name:'Добавить устройство'})).toBeDisabled();
});
