import { defineConfig } from '@playwright/test';
import {browserChannel} from './playwright.browser';
export default defineConfig({testDir:'./tests',testMatch:['portal.spec.ts','diagnostics.spec.ts'],use:{baseURL:'http://127.0.0.1:8080',headless:true,channel:browserChannel()},webServer:{command:'node ../scripts/workspace.mjs demo',url:'http://127.0.0.1:8080/healthz',reuseExistingServer:false,timeout:15000},projects:[{name:'desktop',use:{viewport:{width:1365,height:900}}},{name:'mobile',use:{viewport:{width:320,height:800}}}]});
