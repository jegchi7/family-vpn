import { test, expect } from '@playwright/test';
test('device list, demo download and instructions',async({page})=>{
 await page.goto('/');await expect(page.getByRole('heading',{name:'Всё для подключения.'})).toBeVisible();
 await expect(page.getByRole('heading',{name:'Чужое устройство'})).toHaveCount(0);
 const download=page.waitForEvent('download');await page.getByRole('link',{name:'Демо-файл ↓'}).first().click();expect((await download).suggestedFilename()).toBe('demo-profile.txt');
 await page.getByRole('button',{name:'Как подключиться',exact:true}).first().click();await page.getByRole('button',{name:'Android',exact:true}).click();await expect(page.getByRole('heading',{name:'Подключение Android'})).toBeVisible();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
});
test('status remains explicitly simulated and admin route is separate',async({page,request})=>{
 await page.goto('/');await page.getByRole('button',{name:'Проверка связи'}).click();await expect(page.getByRole('heading',{name:'Здесь пока нет проверки вашего VPN'})).toBeVisible();
 expect((await request.get('/api/v1/admin/overview')).status()).toBe(404);
 // The harness starts two independent processes. Portal readiness does not
 // imply that the separate management demo listener has finished starting.
 await expect.poll(async()=>{try{return (await request.get('http://127.0.0.1:8081/healthz',{timeout:1000})).status();}catch{return 0;}},{timeout:15000}).toBe(200);
 await page.goto('http://127.0.0.1:8081');await expect(page.getByRole('heading',{name:'Отдельный контур.'})).toBeVisible();
});
