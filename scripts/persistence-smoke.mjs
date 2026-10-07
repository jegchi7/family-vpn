// Built-binary integration: persistence across processes and read-only HTTP serving.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const state=mkdtempSync(join(tmpdir(),'family-vpn-smoke-'));
const ext=process.platform==='win32'?'.exe':'';
function ctl(command,args=[],ok=true) {
 const r=spawnSync(join(root,'build',`vpnctl${ext}`),[command,'--root',state,...args],{encoding:'utf8'});
 if(r.error)throw r.error;
 assert.equal(r.status===0,ok,r.stderr);
 return r.stdout;
}
let server;
try {
 ctl('demo-init');
 ctl('demo-rename',['--id','dev-iphone','--name','Persisted smoke phone','--expected-revision','1']);
 ctl('demo-rename',['--id','dev-iphone','--name','Stale edit','--expected-revision','1'],false);
 ctl('demo-rename',['--id','dev-other','--name','Foreign edit','--expected-revision','1'],false);
 ctl('demo-init');
 const status=JSON.parse(ctl('db-status'));
 assert.equal(status.portal.schema_version,6);assert.equal(status.control.schema_version,4);
 const readiness=JSON.parse(ctl('profile-readiness',['--apply'],false));
 assert.equal(readiness.code,'INVALID_TARGET');assert.equal(readiness.ready,false);assert.equal(readiness.read_only,true);assert.equal(readiness.network_changed,false);
 server=spawn(join(root,'build',`portal${ext}`),['--demo','--listen','127.0.0.1:18080','--portal-db',join(state,'portal','state.db'),'--web-dir',join(root,'web','dist')],{stdio:['ignore','pipe','pipe']});
 let failure='', spawnError=false;server.on('error',e=>{failure=e.message;spawnError=true;});server.stderr.on('data',b=>{failure+=b;});
 let ready=false;
 for(let i=0;i<100;i++) {
  if(server.exitCode!==null||spawnError)throw Error(failure||'portal exited');
  try{ready=(await fetch('http://127.0.0.1:18080/readyz')).ok;}catch{}
  if(ready)break;
  await new Promise(r=>setTimeout(r,50));
 }
 assert.ok(ready,'portal did not become ready');
 const me=await (await fetch('http://127.0.0.1:18080/api/v1/me')).json();assert.equal(me.storage,'sqlite');
 const response=await fetch('http://127.0.0.1:18080/api/v1/devices');assert.equal(response.status,200);
 const devices=await response.json();
 assert.ok(JSON.stringify(devices).includes('Persisted smoke phone'));
 assert.ok(!JSON.stringify(devices).includes('Stale edit'));
 assert.equal((await fetch('http://127.0.0.1:18080/api/v1/admin/overview')).status,404);
 console.log('PASS: CLI persistence, repeat init, revision conflict, ownership, SQLite HTTP readiness and listener separation');
} finally {
 if(server?.pid&&server.exitCode===null){await new Promise(r=>{server.once('exit',r);server.kill('SIGTERM');});}
 rmSync(state,{recursive:true,force:true});
}
