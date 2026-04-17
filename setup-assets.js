/**
 * Emberline — Asset download script
 * ──────────────────────────────────
 * Run once: node setup-assets.js
 *
 * Downloads all external dependencies (fonts + crypto library) so
 * Emberline runs fully self-hosted with zero external requests.
 */

const https = require('https');
const fs    = require('fs');
const path  = require('path');

const FONTS_DIR = path.join(__dirname, 'fonts');
const JS_DIR    = path.join(__dirname, 'vendor');

// Create directories
if (!fs.existsSync(FONTS_DIR)) fs.mkdirSync(FONTS_DIR);
if (!fs.existsSync(JS_DIR))    fs.mkdirSync(JS_DIR);

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

// Parse Google Fonts CSS to extract actual .woff2 file URLs
function fetchFontCSS(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; woff2)' } }, res => {
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
  console.log('Downloading NaCl libraries...');
  await download(
    'https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl-fast.min.js',
    path.join(JS_DIR, 'nacl-fast.min.js')
  );
  console.log('  ✓ vendor/nacl-fast.min.js');

  await download(
    'https://cdn.jsdelivr.net/npm/tweetnacl-util@0.15.1/nacl-util.min.js',
    path.join(JS_DIR, 'nacl-util.min.js')
  );
  console.log('  ✓ vendor/nacl-util.min.js');

  // ── 2. Google Fonts ──────────────────────────────────────────────────────────
  console.log('\nFetching font CSS...');
  const fontCSS = await fetchFontCSS(
    'https://fonts.googleapis.com/css2?family=Unbounded:wght@400;500;600;700&family=Inter:wght@300;400;500;600&display=swap'
  );

  // Extract all woff2 URLs
  const urlRegex = /url\((https:\/\/fonts\.gstatic\.com\/[^)]+\.woff2)\)/g;
  const matches = [...fontCSS.matchAll(urlRegex)];
  const uniqueUrls = [...new Set(matches.map(m => m[1]))];
  console.log(`  Found ${uniqueUrls.length} font files`);

  // Download each font file and track filename → url mapping
  const fontMap = {};
  for (const url of uniqueUrls) {
    const filename = url.split('/').pop().split('?')[0] + '.woff2';
    const dest = path.join(FONTS_DIR, filename);
    await download(url, dest);
    fontMap[url] = `/fonts/${filename}`;
    console.log(`  ✓ fonts/${filename}`);
  }

  // ── 3. Build local @font-face CSS ────────────────────────────────────────────
  console.log('\nGenerating fonts/fonts.css...');
  let localCSS = fontCSS;

  // Replace each remote URL with local path
  for (const [remoteUrl, localPath] of Object.entries(fontMap)) {
    localCSS = localCSS.split(`url(${remoteUrl})`).join(`url(${localPath})`);
  }

  // Strip the Google Fonts API comment/charset and keep only @font-face blocks
  const fontFaceBlocks = [...localCSS.matchAll(/@font-face\s*\{[^}]+\}/g)]
    .map(m => m[0]).join('\n\n');

  fs.writeFileSync(path.join(FONTS_DIR, 'fonts.css'), fontFaceBlocks);
  console.log('  ✓ fonts/fonts.css');

  console.log('\nAll assets downloaded. Your folder structure:');
  console.log('  (project root)');
  console.log('  ├── index.html');
  console.log('  ├── server.js');
  console.log('  ├── package.json');
  console.log('  ├── vendor/');
  console.log('  │   ├── nacl-fast.min.js');
  console.log('  │   └── nacl-util.min.js');
  console.log('  └── fonts/');
  console.log('      ├── fonts.css');
  console.log('      └── [woff2 font files]');
  console.log('\nRestart your server and you\'re fully self-hosted.');
}

main().catch(err => {
  console.error('Setup failed:', err.message);
  process.exit(1);
});
