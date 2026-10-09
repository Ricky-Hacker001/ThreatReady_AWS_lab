// Browser end-to-end test. Starts the real server on a temporary data file and drives the console like a learner.
// Run: npm run build && npm run test:e2e
import { chromium, Page } from 'playwright';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import { createApp } from '../../server/app';
import { Store } from '../../server/store';

const root = path.resolve(import.meta.dirname, '../..');
const shots = process.env.SHOTS_DIR; let n = 0;
const shot = async (page: Page, name: string) => { if (shots) { fs.mkdirSync(shots, { recursive: true }); await page.screenshot({ path: path.join(shots, `${String(++n).padStart(2, '0')}-${name}.png`) }); } };
const assert = (c: any, m: string) => { if (!c) throw new Error(`ASSERT: ${m}`); console.log(`  ✓ ${m}`); };

const server = createApp(new Store(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tr-e2e-')), 'store.json')), path.join(root, 'dist')).listen(0);
const base = `http://localhost:${(server.address() as any).port}`;
const exe = fs.existsSync('/opt/pw-browsers/chromium') && fs.statSync('/opt/pw-browsers/chromium').isFile() ? '/opt/pw-browsers/chromium' : undefined;
const browser = await chromium.launch({ executablePath: exe });
const page = await browser.newPage({ viewport: { width: 1500, height: 900 } });
const errors: string[] = []; page.on('pageerror', e => errors.push(e.message)); page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
const confirm = async (label: string) => page.getByRole('dialog').getByRole('button', { name: label, exact: true }).click();
const toast = async (text: string | RegExp) => page.locator('.toast', { hasText: text }).first().waitFor();

try {
  console.log('Start the lab and read the briefing');
  await page.goto(base); await page.getByLabel('Display name').fill('E2E Learner'); await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('dialog', { name: 'Incident briefing' }).waitFor(); await shot(page, 'briefing');
  await page.getByRole('button', { name: /Next: rules/ }).click(); await page.getByRole('button', { name: 'Enter the console' }).click();
  assert(await page.locator('.simbar').innerText().then(t => t.includes('SIMULATION ENVIRONMENT')), 'persistent simulation banner is shown');
  await shot(page, 'home');

  console.log('Acknowledge the ticket');
  await page.getByRole('navigation', { name: 'Services' }).getByRole('button', { name: 'Incident Center' }).click();
  await page.getByRole('button', { name: 'Acknowledge ticket' }).click(); await toast(/acknowledged/);

  console.log('Navigate to a resource and collect evidence');
  await page.getByRole('navigation', { name: 'Services' }).getByRole('button', { name: 'S3', exact: true }).click();
  await page.getByRole('link', { name: 'novacart-internal-docs' }).click();
  await page.getByRole('tab', { name: 'Permissions' }).click(); await shot(page, 's3-permissions');
  const vuln = page.locator('.side').getByRole('tab', { name: /Vulnerabilities/ }); await vuln.click();
  assert((await page.locator('.vulnlist li.found, .vulnlist li.done').count()) === 0, 'opening the page did not mark anything as found');

  console.log('Demonstrate the exposure, then report the finding');
  await page.getByRole('button', { name: 'Send request' }).click(); await page.locator('.note', { hasText: '200 OK' }).waitFor();
  await page.getByRole('button', { name: 'Report finding' }).click(); await page.getByRole('radio', { name: /Publicly exposed S3 bucket/ }).check(); await page.getByRole('button', { name: 'Submit finding' }).click(); await toast(/Finding V2 recorded/);
  assert((await page.locator('.vulnlist li.found').count()) === 1, 'the vulnerability list marks the finding as found');

  console.log('Change the configuration, confirm, and verify');
  await page.locator('.panel', { hasText: 'Block public access (bucket settings)' }).getByRole('button', { name: 'Edit' }).click();
  for (const box of await page.locator('.panel', { hasText: 'Block public access (bucket settings)' }).getByRole('checkbox').all()) await box.check();
  await page.getByRole('button', { name: 'Save changes' }).click(); await page.getByRole('dialog').getByText('Potential operational impact').waitFor(); await shot(page, 'confirm'); await confirm('Confirm'); await toast(/Block Public Access settings updated/);
  await page.locator('.side').getByRole('tab', { name: 'Objectives' }).click();
  assert(await page.locator('.objs li', { hasText: 'Remediate and verify: Publicly exposed S3 bucket' }).innerText().then(t => t.includes('run a verification test')), 'fix alone is not counted as verified');
  await page.getByRole('button', { name: 'Send request' }).click(); await page.locator('.note', { hasText: /Blocked by S3 Block Public Access|AccessDenied/ }).waitFor();
  await page.getByLabel('Requester').selectOption({ label: 'role/nc-app-server-role' }); await page.getByRole('button', { name: 'Send request' }).click(); await page.locator('.note', { hasText: '200 OK' }).waitFor();
  await page.locator('.objs li.done', { hasText: 'Remediate and verify: Publicly exposed S3 bucket' }).waitFor(); assert(true, 'objective completes after passing verification tests'); await shot(page, 'verified');

  console.log('A denied destructive action gives meaningful feedback');
  await page.getByRole('button', { name: 'Delete', exact: true }).click(); await confirm('Delete bucket'); await page.locator('.toast', { hasText: 'Access denied' }).waitFor(); assert(true, 'destructive action denied by learner permissions');

  console.log('Other consoles render and progress persists across reload');
  for (const [svc, text] of [['IAM', 'svc-storefront-app'], ['EC2', 'nc-app-server'], ['VPC', 'Network exposure map'], ['CloudTrail', 'StopLogging'], ['CloudWatch', 'nc-app-cpu-high'], ['Lambda', 'nc-order-processor'], ['KMS', 'alias/novacart-data'], ['Secrets Manager', 'novacart/prod/db-master'], ['Governance', 'Organization structure'], ['Security Findings', 'Publicly exposed S3 bucket'], ['Lab Objectives', 'Level 1']] as const) {
    await page.getByRole('navigation', { name: 'Services' }).getByRole('button', { name: svc, exact: true }).click(); await page.locator('#main').getByText(text).first().waitFor(); if (['VPC', 'CloudTrail', 'IAM'].includes(svc)) await shot(page, svc.toLowerCase());
  }
  assert(true, 'all eleven service consoles and lab pages render');
  await page.reload(); await page.locator('.side').getByRole('tab', { name: /Vulnerabilities 1\/10/ }).waitFor(); assert(true, 'session progress survives a reload');
  await page.locator('.dock').getByRole('tab', { name: 'Activity' }).click(); await page.locator('.dock', { hasText: 's3.putPublicAccessBlock' }).waitFor(); assert(true, 'activity history lists the accepted actions');
  await page.getByRole('button', { name: /E2E Learner/ }).click(); await page.getByRole('button', { name: 'Incident report' }).click(); await page.getByText('(draft)').waitFor(); await page.locator('tr', { hasText: 'V2' }).getByText('Root cause remediated and verified by test.').waitFor(); await shot(page, 'report'); assert(true, 'draft report reflects the verified finding');
  assert(errors.length === 0, `no browser errors (${errors.join(' | ') || 'none'})`);
  console.log('\nBrowser E2E passed');
} catch (e) { if (shots) await page.screenshot({ path: path.join(shots, 'FAILURE.png') }).catch(() => {}); console.error(e, errors); process.exitCode = 1; }
finally { await browser.close(); server.close(); }
