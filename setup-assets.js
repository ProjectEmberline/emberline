/**
 * Emberline — Asset download script
 * ──────────────────────────────────
 * Run once: node setup-assets.js
 *
 * Downloads the fonts and copies the crypto library (from node_modules) so
 * Emberline runs fully self-hosted with zero external requests.
 */

const https = require('https');
const fs    = require('fs');
const path  = require('path');

const FONTS_DIR = path.join(__dirname, 'public', 'fonts');
const JS_DIR    = path.join(__dirname, 'public', 'vendor');

// Create directories
if (!fs.existsSync(FONTS_DIR)) fs.mkdirSync(FONTS_DIR, { recursive: true });
if (!fs.existsSync(JS_DIR))    fs.mkdirSync(JS_DIR, { recursive: true });

// Robust file download:
//   - rejects on any non-2xx status (the original would write a 404 HTML body
//     into nacl-fast.min.js and produce a silently broken build)
//   - follows 301, 302, 303, 307, 308 redirects up to 5 hops
//   - resolves relative Location headers against the current URL
//   - cleans up partial files on any failure path
function download(url, dest, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const file    = fs.createWriteStream(dest);
    const cleanup = () => { try { file.close(); } catch {} fs.unlink(dest, () => {}); };

    const req = https.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } }, res => {
      const code = res.statusCode;

      // Redirect: drain body, clean placeholder, recurse
      if ([301, 302, 303, 307, 308].includes(code)) {
        res.resume();
        file.close();
        fs.unlink(dest, () => {});
        if (redirectsLeft <= 0) return reject(new Error(`Too many redirects: ${url}`));
        const next = new URL(res.headers.location, url).toString();
        return download(next, dest, redirectsLeft - 1).then(resolve, reject);
      }

      // Any other non-2xx is a hard failure — don't save the body
      if (code < 200 || code >= 300) {
        res.resume();
        cleanup();
        return reject(new Error(`HTTP ${code} fetching ${url}`));
      }

      res.pipe(file);
      file.on('finish', () => { file.close(); resolve(dest); });
      file.on('error',  err => { cleanup(); reject(err); });
    });

    req.on('error', err => { cleanup(); reject(err); });
  });
}

// Google Fonts picks the font format from the User-Agent. A generic UA gets
// .ttf links; a current desktop browser UA gets .woff2 split by unicode-range.
const FONT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

// Unicode subsets to self-host. The service worker pre-caches every font file,
// so shipping cyrillic/greek/vietnamese would bloat every install.
const FONT_SUBSETS = new Set(['latin', 'latin-ext']);

function fetchFontCSS(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': FONT_UA } }, res => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
      }
      let data = '';
      res.on('data',  chunk => data += chunk);
      res.on('end',   () => resolve(data));
      res.on('error', reject);
    }).on('error', reject);
  });
}

async function main() {
  console.log('Emberline asset setup\n');

  // ── 1. TweetNaCl ────────────────────────────────────────────────────────────
  // Copied from node_modules rather than downloaded: npm verifies each package
  // against the integrity hash pinned in package-lock.json, so a tampered
  // CDN or registry response fails `npm ci` instead of shipping to users.
  console.log('Copying NaCl libraries from node_modules...');
  for (const [pkgFile, name] of [
    ['tweetnacl/nacl-fast.min.js',      'nacl-fast.min.js'],
    ['tweetnacl-util/nacl-util.min.js', 'nacl-util.min.js'],
  ]) {
    fs.copyFileSync(require.resolve(pkgFile), path.join(JS_DIR, name));
    console.log(`  ✓ public/vendor/${name}`);
  }

  // ── 2. Google Fonts ──────────────────────────────────────────────────────────
  console.log('\nFetching font CSS...');
  const fontCSS = await fetchFontCSS(
    'https://fonts.googleapis.com/css2?family=Unbounded:wght@400;500;600;700&family=Inter:wght@300;400;500;600&display=swap'
  );

  // Google prefixes each @font-face block with a /* subset */ comment.
  // Keep only the blocks for the subsets we self-host.
  const blocks = [...fontCSS.matchAll(/\/\*\s*([\w-]+)\s*\*\/\s*(@font-face\s*\{[^}]+\})/g)]
    .filter(m => FONT_SUBSETS.has(m[1]))
    .map(m => m[2]);
  if (blocks.length === 0) throw new Error('No @font-face blocks found for subsets: ' + [...FONT_SUBSETS].join(', '));

  const urlRegex = /url\((https:\/\/fonts\.gstatic\.com\/[^)]+\.woff2)\)/g;
  const uniqueUrls = [...new Set(blocks.flatMap(b => [...b.matchAll(urlRegex)].map(m => m[1])))];
  console.log(`  Found ${blocks.length} @font-face blocks, ${uniqueUrls.length} font files`);

  // Download each font file and track filename → url mapping
  const fontMap = {};
  for (const url of uniqueUrls) {
    const filename = url.split('/').pop().split('?')[0];
    const dest = path.join(FONTS_DIR, filename);
    await download(url, dest);
    fontMap[url] = `/fonts/${filename}`;
    console.log(`  ✓ public/fonts/${filename}`);
  }

  // ── 3. Build local @font-face CSS ────────────────────────────────────────────
  console.log('\nGenerating public/fonts/fonts.css...');
  const fontFaceBlocks = blocks
    .map(b => b.replace(urlRegex, (_, remoteUrl) => `url(${fontMap[remoteUrl]})`))
    .join('\n\n');

  // Any remaining remote URL would be blocked by CSP (font-src 'self') and
  // silently fall back to system fonts. Fail the build instead.
  if (/url\(\s*['"]?https?:/i.test(fontFaceBlocks)) {
    throw new Error('fonts.css still references remote URLs (unexpected format from Google Fonts?)');
  }

  fs.writeFileSync(path.join(FONTS_DIR, 'fonts.css'), fontFaceBlocks);
  console.log('  ✓ public/fonts/fonts.css');

  console.log('\nAll assets downloaded. Your folder structure:');
  console.log('  (project root)');
  console.log('  ├── server.js');
  console.log('  ├── package.json');
  console.log('  └── public/');
  console.log('      ├── index.html');
  console.log('      ├── vendor/');
  console.log('      │   ├── nacl-fast.min.js');
  console.log('      │   └── nacl-util.min.js');
  console.log('      └── fonts/');
  console.log('          ├── fonts.css');
  console.log('          └── [woff2 font files]');
  console.log('\nRestart your server and you\'re fully self-hosted.');
}

main().catch(err => {
  console.error('Setup failed:', err.message);
  process.exit(1);
});
