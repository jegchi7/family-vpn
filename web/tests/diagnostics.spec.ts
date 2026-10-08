import {test,expect,type Page} from '@playwright/test';

type State='unchecked'|'stored'|'matched'|'conflict'|'expired'|'stale';
const clock=new Date('2026-10-08T12:00:00Z');
function diagnostic(configuration:State,source:'none'|'snapshot'|'native_readback'='none',checked=clock.getTime()){
 return {connection:'unknown',configuration,source,clientVerification:'unchecked',...(source==='none'?{}:{checkedAt:new Date(checked).toISOString(),expiresAt:new Date(checked+60000).toISOString()})};
}
function device(diagnostics:ReturnType<typeof diagnostic>|undefined,protocol='awg'){
 return {id:'test-device',name:'Телефон для проверки',os:'android',state:'pending',revision:1,generation:1,owner_id:'test-owner',owner_login:'Тестовый пользователь',profiles:[{id:'test-profile',protocol,state:'pending',format:protocol==='awg'?'awg-3.1-conf':'vless-reality-uri',stored:true,...(diagnostics?{diagnostics}:{})}]};
}
async function mockViews(page:Page,admin:boolean,current:()=>ReturnType<typeof device>[]){
 const requests:{method:string;path:string}[]=[];
 await page.route('**/api/v1/**',async route=>{
  const url=new URL(route.request().url());const path=url.pathname.replace('/api/v1','');requests.push({method:route.request().method(),path});
  let result:unknown;
  switch(path){
   case '/me':result={id:'test-owner',display_name:'Тестовый пользователь',role:admin?'admin':'user',mode:admin?'local-admin':'local-auth',csrf_token:''};break;
   case '/devices':result={items:current()};break;
   case '/devices/quota':result={limit:5,used:1,remaining:4};break;
   case '/status':case '/instructions':result={items:[]};break;
   case '/admin/overview':result={total_devices:1,components:[],message:'Проверка отображения'};break;
   case '/admin/devices':result={items:current(),next_cursor:''};break;
   case '/auth/session/touch':await route.fulfill({status:204});return;
   default:await route.abort();return;
  }
  await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(result)});
 });
 return requests;
}

for(const admin of [false,true]){
 const view=admin?'админка':'кабинет';
 for(const configuration of ['matched','conflict'] as const){
 test(`synthetic ${view}: configuration ${configuration} is separate from connection and expires without refresh`,async({page},testInfo)=>{
  await page.clock.install({time:clock});
  const requests=await mockViews(page,admin,()=>[device(diagnostic(configuration,'native_readback'),admin?'reality':'awg')]);
  await page.goto('/');const card=page.getByRole('article',{name:'Телефон для проверки'});
  await expect(card.getByText(configuration==='matched'?'Совпадает по сверке':'Обнаружено расхождение',{exact:true})).toBeVisible();
  await expect(card.getByText('Нет данных',{exact:true})).toBeVisible();
  await expect(card.getByText('Сверка с прочитанными настройками',{exact:false})).toBeVisible();
  await card.getByText('Проверки подключения',{exact:true}).click();
  await expect(card.getByText('Не проверен',{exact:true})).toBeVisible();
  await expect(card.getByText('Не проверена',{exact:true})).toBeVisible();
  await expect(card.getByText('Не проверены',{exact:true})).toBeVisible();
  await expect(card.getByRole('link')).toHaveCount(0);
  await expect(card.getByText('Подключено',{exact:true})).toHaveCount(0);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  if(configuration==='matched')await page.screenshot({path:`../build/protocol-status-${admin?'admin':'user'}-${testInfo.project.name}.png`,fullPage:true});
  const reads=requests.filter(r=>r.path===('/'+(admin?'admin/':'')+'devices')).length;
  await page.clock.fastForward(60001);
  await expect(card.getByText('Результат устарел',{exact:true})).toBeVisible();
  await expect(card.getByText('Совпадает по сверке',{exact:true})).toHaveCount(0);
  await expect(card.getByText('Обнаружено расхождение',{exact:true})).toHaveCount(0);
  expect(requests.filter(r=>r.path===('/'+(admin?'admin/':'')+'devices'))).toHaveLength(reads);
  expect(requests.filter(r=>r.method!=='GET'&&r.path!=='/auth/session/touch')).toHaveLength(0);
 });
 }

 test(`synthetic ${view}: refresh shows latest conflict; missing and future evidence cannot imply online`,async({page})=>{
  await page.clock.install({time:clock});
  let current=device(diagnostic('matched','snapshot'));
  const requests=await mockViews(page,admin,()=>[current]);
  await page.goto('/');const card=page.getByRole('article',{name:'Телефон для проверки'});
  await expect(card.getByText('Совпадает по сверке',{exact:true})).toBeVisible();
  await expect(card.getByText('Сверка с сохранённой копией',{exact:false})).toBeVisible();
  current=device(diagnostic('conflict','native_readback'));
  await page.getByRole('button',{name:'Обновить список',exact:true}).click();
  await expect(card.getByText('Обнаружено расхождение',{exact:true})).toBeVisible();
  await expect(card.getByText('Совпадает по сверке',{exact:true})).toHaveCount(0);
  current=device(diagnostic('matched','native_readback',clock.getTime()+30000));
  await page.getByRole('button',{name:'Обновить список',exact:true}).click();
  await expect(card.getByText('Нужна новая сверка',{exact:true})).toBeVisible();
  await page.clock.fastForward(30001);
  await expect(card.getByText('Нужна новая сверка',{exact:true})).toBeVisible();
  current=device(undefined);
  await page.getByRole('button',{name:'Обновить список',exact:true}).click();
  await expect(card.getByText('Сохранена, ждёт сверки',{exact:true})).toBeVisible();
  await expect(card.getByText('Нет данных',{exact:true})).toBeVisible();
  current=device({...diagnostic('matched','native_readback'),checkedAt:'invalid',expiresAt:'invalid'});
  await page.getByRole('button',{name:'Обновить список',exact:true}).click();
  await expect(card.getByText('Проверка не выполнена',{exact:true})).toBeVisible();
  await expect(card.getByText('Совпадает по сверке',{exact:true})).toHaveCount(0);
  expect(requests.filter(r=>r.method!=='GET'&&r.path!=='/auth/session/touch')).toHaveLength(0);
 });
}
