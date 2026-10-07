import { spawnSync, spawn } from 'node:child_process';
import { mkdirSync, existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
process.chdir(root);
const npm=process.platform==='win32'?'npm.cmd':'npm';
const ext=process.platform==='win32'?'.exe':'';
function run(cmd,args){const r=spawnSync(cmd,args,{stdio:'inherit',shell:process.platform==='win32' && cmd===npm});if(r.error){console.error(r.error.message);process.exit(1)}if(r.status!==0)process.exit(r.status??1)}
const cmd=process.argv[2];
if(cmd==='build') {
 run(npm,['--prefix','web','run','check']);run(npm,['--prefix','web','run','build']);mkdirSync('build',{recursive:true});
 for(const name of ['portal','admin','node-agent','hop-controller','foreign-probe','vpnctl'])run('go',['build','-buildvcs=false','-trimpath','-o',`build/${name}${ext}`,`./cmd/${name}`]);
} else if(cmd==='check') {
 run('go',['vet','./...']);run('go',['test','-race','./...']);
 const before=readFileSync('web/src/lib/api.generated.ts','utf8');run(npm,['--prefix','web','run','api:generate']);
 if(readFileSync('web/src/lib/api.generated.ts','utf8')!==before){console.error('Generated API types were stale. Review and commit the generated diff.');process.exit(1)}
 run(npm,['--prefix','web','run','check']);run(npm,['--prefix','web','run','build']);
} else if(cmd==='auth'||cmd==='auth-test') {
 if(['portal','vpnctl'].some(name=>!existsSync(`build/${name}${ext}`))||!existsSync('web/dist/index.html')){console.error('Run npm run setup && npm run build first.');process.exit(1)}
 const state=cmd==='auth-test'?process.env.FVPN_TEST_STATE:'var/auth';
 if(!state){console.error('auth-test requires the isolated state path supplied by Playwright config.');process.exit(1)}
 run(resolve(`build/vpnctl${ext}`),['auth-init','--root',state]);
 const child=spawn(resolve(`build/portal${ext}`),['--local-auth','--listen','127.0.0.1:8443','--portal-db',`${state}/portal/state.db`,'--tls-cert',`${state}/tls/local-cert.pem`,'--tls-key',`${state}/tls/local-key.pem`,'--web-dir','web/dist'],{stdio:'inherit'});
 let stopping=false;function stop(){if(!stopping){stopping=true;child.kill('SIGTERM');}}
 process.on('SIGINT',stop);process.on('SIGTERM',stop);
 child.on('error',e=>{console.error(e.message);process.exitCode=1;stop();});child.on('exit',code=>{if(!stopping)process.exitCode=code||1;});
 console.log('Local HTTPS auth: https://127.0.0.1:8443 | Self-signed test certificate | Ctrl+C to stop');
 } else if(cmd==='admin'||cmd==='admin-test') {
 const state=cmd==='admin-test'?process.env.FVPN_ADMIN_TEST_STATE:'var/admin';
 const portal=cmd==='admin-test'?`${state}/users`:'var/auth';
 const master=cmd==='admin-test'?`${state}-secrets/master.key`:'var/admin-secrets/master.key';
 if(!state){console.error('admin-test requires isolated state path');process.exit(1)}
 if(cmd==='admin-test')run(resolve(`build/vpnctl${ext}`),['admin-key-create','--root',state,'--master-key',master]);
 run(resolve(`build/vpnctl${ext}`),['auth-init','--root',portal]);
 run(resolve(`build/vpnctl${ext}`),['admin-init','--root',state,'--master-key',master]);
 const child=spawn(resolve(`build/admin${ext}`),['--local-auth','--listen','127.0.0.1:9443','--portal-db',`${portal}/portal/state.db`,'--admin-db',`${state}/auth/state.db`,'--master-key',master,'--tls-cert',`${state}/tls/local-cert.pem`,'--tls-key',`${state}/tls/local-key.pem`,'--web-dir','web/dist'],{stdio:'inherit'});
 let stopping=false;function stop(){if(!stopping){stopping=true;child.kill('SIGTERM');}}
 process.on('SIGINT',stop);process.on('SIGTERM',stop);
 child.on('error',e=>{console.error(e.message);process.exitCode=1;stop();});child.on('exit',code=>{if(!stopping)process.exitCode=code||1;});
 console.log('Local MFA admin: https://127.0.0.1:9443 | Ctrl+C to stop');
} else if(cmd==='demo') {
 if(['portal','admin','vpnctl'].some(name=>!existsSync(`build/${name}${ext}`))||!existsSync('web/dist/index.html')){console.error('Run npm run setup && npm run build first.');process.exit(1)}
 run(resolve(`build/vpnctl${ext}`),['demo-init']);
 const children=['portal','admin'].map(name=>spawn(resolve(`build/${name}${ext}`),['--demo','--web-dir','web/dist'],{stdio:'inherit'}));
 let stopping=false;function stop(){if(stopping)return;stopping=true;for(const child of children)child.kill('SIGTERM');}
 process.on('SIGINT',stop);process.on('SIGTERM',stop);
 for(const child of children){child.on('error',e=>{console.error(e.message);process.exitCode=1;stop()});child.on('exit',code=>{if(!stopping){process.exitCode=code||1;stop();}})}
 console.log('Portal: http://127.0.0.1:8080 | Admin: http://127.0.0.1:8081 | Ctrl+C to stop');
} else { console.error('Expected build, check, demo, auth or auth-test');process.exit(2); }
