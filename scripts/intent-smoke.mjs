// CLI admission/persistence smoke. No socket, credentials or runtime/network mutations.
import {spawnSync,spawn} from 'node:child_process';
import {mkdtempSync,rmSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const state=mkdtempSync(join(tmpdir(),'family-vpn-intents-'));
const exe=resolve(root,`build/hop-controller${process.platform==='win32'?'.exe':''}`);
const db=join(state,'private','control.db');
function run(args,input){const r=spawnSync(exe,args,{encoding:'utf8',input:input===undefined?undefined:JSON.stringify(input),cwd:root});assert.ifError(r.error);return r;}
const base=['--fake-stand','--control-db',db,'--node','stand-ru'];
const env={schema_version:1,operation_id:'smoke-operation',type:'EnsureDeviceProfiles',target_id:'synthetic-profile',expected_revision:0,payload:{generation:1}};
async function workerEvent(){
 const child=spawn(exe,[...base,'--command','worker','--poll-ms','100','--socket',join(state,'missing-agent.sock')],{cwd:root,stdio:['ignore','pipe','pipe']});
 const exited=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal}));});
 let buffer='',timer;
 try{
  const event=await new Promise((resolve,reject)=>{
   timer=setTimeout(()=>reject(new Error('worker report timeout')),6000);
   child.once('error',reject);child.once('close',()=>reject(new Error('worker exited before report')));
   child.stdout.on('data',chunk=>{buffer+=chunk.toString();if(buffer.includes('\n')){try{resolve(JSON.parse(buffer.split('\n')[0]));}catch(e){reject(e)}}});
  });
  child.kill('SIGTERM');const exit=await exited;assert.equal(exit.code,0);assert.equal(exit.signal,null);return event;
 }finally{
  clearTimeout(timer);if(child.exitCode===null){child.kill('SIGKILL');await exited.catch(()=>{});}
 }
}
try{
 let r=run(['--command','init','--control-db',db]);assert.equal(r.status,2);assert.equal(existsSync(db),false);
 r=run([...base,'--command','init']);assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).schema_version,4);
 r=run([...base,'--command','enqueue','--idempotency-key','one-request'],env);assert.equal(r.status,0,r.stderr);const first=JSON.parse(r.stdout);assert.equal(first.state,'queued');assert.equal(first.attempts,0);assert.equal(first.checkpoint,'intent');assert.equal('Envelope' in first,false);assert.equal('envelope' in first,false);
 r=run([...base,'--command','enqueue','--idempotency-key','one-request'],{...env,operation_id:'ignored-retry-id'});assert.equal(r.status,0,r.stderr);assert.deepEqual(JSON.parse(r.stdout),first);
 r=run([...base,'--command','enqueue','--idempotency-key','one-request'],{...env,target_id:'changed'});assert.equal(r.status,2);assert.equal(r.stderr.trim(),'idempotency_conflict');assert.equal(r.stdout,'');
 r=run([...base,'--command','enqueue','--idempotency-key','stale-request'],{...env,operation_id:'stale-operation',expected_revision:1});assert.equal(r.status,2);assert.equal(r.stderr.trim(),'revision_conflict');
 r=run([...base,'--command','enqueue','--idempotency-key','invalid-request'],{...env,command:'arbitrary'});assert.equal(r.status,2);assert.equal(r.stderr.trim(),'invalid_intent');
 r=run([...base,'--command','status','--operation-id',env.operation_id]);assert.equal(r.status,0,r.stderr);assert.deepEqual(JSON.parse(r.stdout),first);
 r=run([...base,'--command','cancel','--operation-id',env.operation_id]);assert.equal(r.status,0,r.stderr);const cancelled=JSON.parse(r.stdout);assert.equal(cancelled.state,'cancelled');assert.equal(cancelled.attempts,0);
 r=run([...base,'--command','cancel','--operation-id',env.operation_id]);assert.equal(r.status,0,r.stderr);assert.deepEqual(JSON.parse(r.stdout),cancelled);
 r=run([...base,'--command','enqueue','--idempotency-key','one-request'],env);assert.equal(r.status,0,r.stderr);assert.deepEqual(JSON.parse(r.stdout),cancelled);
 const pending={...env,operation_id:'worker-operation',target_id:'worker-profile'};r=run([...base,'--command','enqueue','--idempotency-key','worker-request'],pending);assert.equal(r.status,0,r.stderr);
 r=run([...base,'--command','list','--limit','1']);assert.equal(r.status,0,r.stderr);const page=JSON.parse(r.stdout);assert.equal(page.items.length,1);assert.equal(page.items[0].state,'cancelled');assert.ok(page.next_cursor>0);
 r=run([...base,'--command','list','--limit','1','--after',String(page.next_cursor)]);assert.equal(r.status,0,r.stderr);const last=JSON.parse(r.stdout);assert.equal(last.items[0].operation_id,pending.operation_id);assert.equal(last.next_cursor,undefined);
 r=run([...base,'--command','worker','--poll-ms','99']);assert.equal(r.status,2);assert.equal(r.stderr.trim(),'invalid_intent');
 const delayed=await workerEvent();assert.equal(delayed.state,'reconciling');assert.equal(delayed.attempts,1);assert.equal(delayed.last_error_code,'agent_unavailable');assert.ok(delayed.next_attempt_at);
 r=run([...base,'--command','cancel','--operation-id',pending.operation_id]);assert.equal(r.status,2);assert.equal(r.stderr.trim(),'revision_conflict');
 const retried=await workerEvent();assert.equal(retried.operation_id,pending.operation_id);assert.equal(retried.state,'reconciling');assert.equal(retried.attempts,2);assert.equal(retried.consecutive_failures,2);assert.ok(Date.now()>=Date.parse(delayed.next_attempt_at));
 r=run([...base,'--command','status','--operation-id',pending.operation_id]);assert.equal(r.status,0,r.stderr);assert.deepEqual(JSON.parse(r.stdout),retried);
 console.log('PASS: admission/replay/conflicts, queued cancellation/paging, unavailable-agent worker retries persisted across process restart, SIGTERM; no runtime applied');
}finally{rmSync(state,{recursive:true,force:true});}
