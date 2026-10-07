// Explicit local fallback when the bundled Chromium cannot be installed.
// Unset or empty keeps Playwright's bundled browser; no custom executable paths.
export function browserChannel(value = process.env.FVPN_TEST_BROWSER): 'chrome' | 'msedge' | undefined {
 if(!value)return undefined;
 if(value==='chrome'||value==='msedge')return value;
 throw new Error('FVPN_TEST_BROWSER must be chrome or msedge; unset it to use bundled Chromium.');
}
