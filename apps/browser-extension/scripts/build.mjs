import { cp, mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repo = resolve(root, '../..');
execFileSync('cargo', ['build', '--manifest-path', join(root, 'policy/Cargo.toml'), '--target-dir', join(root, 'policy/target'), '--target', 'wasm32-unknown-unknown', '--release', '--locked'], { stdio: 'inherit', cwd: root });
const source = join(root, 'src');
const locales = await readdir(join(source, '_locales'));
const catalogs = await Promise.all(locales.map(async locale => JSON.parse(await readFile(join(source, '_locales', locale, 'messages.json'), 'utf8'))));
const canonical = Object.keys(catalogs[locales.indexOf('en')]).sort().join('\n');
for (const catalog of catalogs) {
  if (Object.keys(catalog).sort().join('\n') !== canonical) throw new Error('Locale keys differ');
}
for (const browser of ['chromium', 'firefox']) {
  const output = join(root, 'dist', browser);
  await mkdir(join(output, 'icons'), { recursive: true });
  await cp(join(source, 'ui'), join(output, 'ui'), { recursive: true });
  await cp(join(source, '_locales'), join(output, '_locales'), { recursive: true });
  for (const name of ['background.js', 'controller.js']) await cp(join(source, name), join(output, name));
  await cp(join(root, 'policy/target/wasm32-unknown-unknown/release/nrr_browser_policy.wasm'), join(output, 'policy.wasm'));
  for (const size of [16, 24, 32, 48, 64, 128]) {
    const name = `icon-${size}.png`;
    const icon = await readFile(join(repo, 'assets/icons/app', name));
    if (icon.length < 24 || icon.readUInt32BE(16) !== size || icon.readUInt32BE(20) !== size) throw new Error(`Invalid icon ${name}`);
    await writeFile(join(output, 'icons', name), icon);
  }
  await cp(join(root, 'manifests', `${browser}.json`), join(output, 'manifest.json'));
  console.log(output);
}
