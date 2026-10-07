import {defineConfig} from '@playwright/test';
import {mkdtempSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {browserChannel} from './playwright.browser';
// Shared with workers and the web server; a fresh store per invocation avoids rate-limit carryover.
process.env.FVPN_ADMIN_TEST_STATE??=mkdtempSync(join(realpathSync(tmpdir()),'family-vpn-admin-e2e-'));
export default defineConfig({testDir:'./tests',testMatch:'admin.spec.ts',workers:1,use:{baseURL:'https://127.0.0.1:9443',headless:true,ignoreHTTPSErrors:true,channel:browserChannel()},webServer:{command:'node ../scripts/workspace.mjs admin-test',url:'https://127.0.0.1:9443/healthz',ignoreHTTPSErrors:true,reuseExistingServer:false,timeout:15000},projects:[{name:'desktop',use:{viewport:{width:1365,height:900}}},{name:'mobile',use:{viewport:{width:320,height:800}}}]});
