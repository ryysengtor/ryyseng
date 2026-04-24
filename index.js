'use strict';

require('dotenv').config();

const axios = require('axios');
axios.defaults.timeout = parseInt(process.env.AXIOS_DEFAULT_TIMEOUT || '30000', 10);

const express = require('express');
const path    = require('path');
const fs      = require('fs');
const moment  = require('moment-timezone');

const C = require('./lib/config');
const { RUNTIME, DATA_DIR: _DATA_DIR } = require('./lib/env-detect');
const {
  setupCompression,
  setupCors,
  setupBodyParsers,
  setupSecurityHeaders,
} = require('./lib/middleware');

const { adminAuth, verifyToken } = require('./lib/auth');

const { DB_BACKEND } = require('./lib/db');
const { _cdnAccounts } = require('./lib/cdn');

const { getEffectiveSettings } = require('./lib/models');

const storeRouter    = require('./routes/store');
const adminRouter    = require('./routes/admin');
const otpRouter      = require('./routes/otp');
const chatRouter     = require('./routes/chat');
const userRouter     = require('./routes/user');
const reviewsRouter  = require('./routes/reviews');
const cdnRouter      = require('./routes/cdn');
const renewRouter    = require('./routes/renew');
const resellerRouter = require('./routes/reseller');
const sewabotRouter  = require('./routes/sewabot');

function loadEndpointRouters(dir) {
  const routers = [];
  const _baseDir = path.resolve(dir);
  if (!fs.existsSync(_baseDir)) return routers;

  function _walk(current) {

    const resolved = path.resolve(current);
    if (!resolved.startsWith(_baseDir)) return;

    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        _walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith('.js')) {
        try {
          const router = require(fullPath);
          routers.push(router);
        } catch (e) {
          console.error('[autoload] Failed to load', fullPath, ':', e.message);
        }
      }
    }
  }

  _walk(_baseDir);
  return routers;
}

const endpointRouters = loadEndpointRouters(path.join(__dirname, 'routes', 'endpoints'));
console.log('[autoload] Endpoint routers loaded:', endpointRouters.length);



const app = express();

app.set('trust proxy', 1);
setupCompression(app);
setupCors(app);
setupBodyParsers(app);
setupSecurityHeaders(app);


app.use(function(req, res, next) {
  res.setTimeout(120000, function() {
    if (!res.headersSent) res.status(503).json({ ok: false, message: 'Request timeout.' });
  });
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
try { app.use(express.static(path.resolve('/var/task/public'))); } catch(e){}

app.use('/media', express.static(path.join(__dirname, 'media')));
try { app.use('/media', express.static(path.resolve('/var/task/media'))); } catch(e){}

app.use(storeRouter);
app.use(adminRouter);
app.use(otpRouter);
app.use(chatRouter);
app.use(userRouter);
app.use(reviewsRouter);
app.use(cdnRouter);
app.use(renewRouter);
app.use(resellerRouter);
app.use(sewabotRouter);

endpointRouters.forEach(function(router) { app.use('/', router); });

app.get('/api/endpoints', function(req, res) {
  var routers = [
    ...endpointRouters,
  ];
  var list = [];
  routers.forEach(function(r) {
    if (!r.metadata) return;
    if (Array.isArray(r.metadata)) {
      r.metadata.forEach(function(m) { list.push(m); });
    } else {
      list.push(r.metadata);
    }
  });
  var grouped = {};
  list.forEach(function(ep) {
    var cat = (ep.category || 'OTHER').toUpperCase();
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push(ep);
  });
  res.json({ ok: true, total: list.length, categories: grouped });
});

app.get('/health', function(req, res) {
  res.json({
    ok       : true,
    uptime   : Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    database : { backend: DB_BACKEND, ready: true },
  });
});

// ── /api/cron/run — endpoint ini dipertahankan untuk kompatibilitas Vercel
//    scheduler, tapi sekarang merupakan no-op karena semua proses sudah
//    event-driven via event-trigger.js. Tidak perlu sweep global lagi.
app.get('/api/cron/run', async function(req, res) {
  const secret   = process.env.CRON_SECRET || '';
  const provided = req.headers['x-cron-secret'] || req.query.secret || '';
  if (!secret || provided !== secret) {
    return res.status(401).json({ ok: false, message: 'Unauthorized.' });
  }
  const et = require('./lib/event-trigger');
  res.json({ ok: true, message: 'Semua proses sudah event-driven — tidak ada sweep global.', watchers: et._status(), ts: new Date().toISOString() });
});

app.get('/ready', async function(req, res) {
  try {
    await getEffectiveSettings();
    res.json({ ok: true, message: 'Ready' });
  } catch(e) {
    res.status(503).json({ ok: false, message: 'Not ready: ' + e.message });
  }
});



const ALLOWED_PAGES = new Set([
  'index.html', 'otp.html', 'pay.html', 'renew.html',
  'track.html', 'upload.html', 'ulasan.html', 'chat.html',
  'produk.html', 'cpanel.html', 'admin.html', 'sw.js',
  'docs.html', 'manifest.json',
]);

function sendPage(res, name) {
  if (!ALLOWED_PAGES.has(name)) {
    return res.status(404).send('Page not found');
  }

  const publicDir = path.resolve(__dirname, 'public');
  const filePath  = path.resolve(publicDir, name);

  if (!filePath.startsWith(publicDir + path.sep) && filePath !== publicDir) {
    return res.status(403).send('Access denied');
  }

  const candidates = [
    filePath,
    path.resolve(process.cwd(), 'public', name),
    path.resolve('/var/task/public', name),
  ];

  function tryNext(i) {
    if (i >= candidates.length) {
      return res.status(404).send('Page not found');
    }
    const candidate = candidates[i];
    if (!candidate.startsWith(path.resolve(__dirname, 'public')) &&
        !candidate.startsWith(path.resolve(process.cwd(), 'public')) &&
        !candidate.startsWith('/var/task/public')) {
      return tryNext(i + 1);
    }
    res.sendFile(candidate, function(err) {
      if (err) tryNext(i + 1);
    });
  }
  tryNext(0);
}

app.get('/',       function(_, res) { sendPage(res, 'index.html'); });
app.get('/otp',    function(_, res) { sendPage(res, 'otp.html'); });
app.get('/pay',    function(_, res) { sendPage(res, 'pay.html'); });
app.get('/renew',  function(_, res) { sendPage(res, 'renew.html'); });
app.get('/track',  function(_, res) { sendPage(res, 'track.html'); });
app.get('/upload', function(_, res) { sendPage(res, 'upload.html'); });
app.get('/ulasan', function(_, res) { sendPage(res, 'ulasan.html'); });
app.get('/chat',   function(_, res) { sendPage(res, 'chat.html'); });
app.get('/produk', function(_, res) { sendPage(res, 'produk.html'); });
app.get('/cpanel', function(_, res) {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.set('Cache-Control', 'no-store, no-cache, private');
  sendPage(res, 'cpanel.html');
});

app.get('/' + C.store.adminPath, function(_, res) {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.set('Cache-Control', 'no-store, no-cache, private');
  sendPage(res, 'admin.html');
});

app.get('/sw.js', function(_, res) {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'no-cache');
  sendPage(res, 'sw.js');
});

app.get('/api-docs', function(_, res) { res.redirect(301, '/docs'); }); // fix: api.html tidak ada, redirect ke /docs
app.get('/docs',     function(_, res) { sendPage(res, 'docs.html'); });

app.get('/manifest.json', async function(_, res) {
  try {
    const stg     = await getEffectiveSettings();
    const name    = stg.storeName   || C.store.name;
    const iconSrc = stg.appLogoUrl  || C.store.appLogoUrl || '/media/icon.jpg';
    const manifest = {
      name            : name,
      short_name      : name,
      description     : 'Toko digital premium – panel, OTP, dan lebih',
      start_url       : '/',
      display         : 'standalone',
      background_color: '#07050f',
      theme_color     : stg.primaryColor || '#07050f',
      orientation     : 'portrait-primary',
      icons: [
        { src: iconSrc, sizes: '192x192', type: iconSrc.endsWith('.jpg') || iconSrc.endsWith('.jpeg') ? 'image/jpeg' : 'image/png', purpose: 'any maskable' },
        { src: iconSrc, sizes: '512x512', type: iconSrc.endsWith('.jpg') || iconSrc.endsWith('.jpeg') ? 'image/jpeg' : 'image/png', purpose: 'any maskable' },
      ],
      shortcuts: [
        { name: 'Cek Order', url: '/track',  description: 'Lihat riwayat order' },
        { name: 'OTP Store', url: '/otp',    description: 'Beli nomor OTP' },
        { name: 'Ulasan',    url: '/ulasan', description: 'Baca & tulis ulasan pelanggan' },
        { name: 'Live Chat', url: '/chat',   description: 'Chat komunitas ' + name },
        { name: 'Produk',    url: '/produk', description: 'Detail produk lengkap' },
      ],
    };
    res.setHeader('Content-Type',  'application/manifest+json');
    res.setHeader('Cache-Control', 'no-cache');
    res.json(manifest);
  } catch(e) {
    res.setHeader('Content-Type', 'application/manifest+json');
    res.setHeader('Cache-Control', 'no-cache');
    sendPage(res, 'manifest.json');
  }
});

app.use(function(err, req, res, next) {
  console.error('[unhandled-error]', req.method, req.path, err.message);
  if (res.headersSent) return;
  res.status(err.status || 500).json({ ok: false, message: err.message || 'Terjadi kesalahan internal.' });
});

app.use(function(_, res) { res.redirect('/'); });

if (require.main === module) {
  const asciiArt = () => {
    console.log(`
\x1b[32m
__   ___            _   _
\\ \\ / (_)_  _____  | | | | __ _ _ __  _____   _
 \\ V /| \\ \\/ / _ \\ | |_| |/ _\` | '_ \\|_  / | | |
  | | | |>  <  __/ |  _  | (_| | | | |/ /| |_| |
  |_| |_/_/\\_\\___| |_| |_|\\__,_|_| |_/___||__, |
                                           |___/\x1b[0m
`);
  };
  asciiArt();

  const tz  = 'Asia/Jakarta';
  const now = moment().tz(tz).format('dddd, D MMMM YYYY — HH:mm:ss z');

  const _dbStatus = DB_BACKEND === 'dongtube-external'
    ? '✅ DongtubeDB External (' + (process.env.DTDB_URL || 'https://dongtube.my.id') + ')'
    : '✅ DongtubeDB (Local · WAL · ACID · B-Tree Index)';

  const _cdnAccList = _cdnAccounts();
  const _cdnStatus  = _cdnAccList[0].backend === 'dongtube-external'
    ? '✅ DongtubeDB External CDN (' + (process.env.DTDB_URL || 'https://dongtube.my.id') + ')'
    : '✅ DongtubeDB Local CDN (' + _cdnAccList[0].name + ')';

  console.log('🟢  Dongtube v2      | http://localhost:' + C.port);
  console.log('🖥️  Environment       | ' + RUNTIME.label + ' · DATA_DIR: ' + _DATA_DIR);
  console.log('🔐  Admin panel       | http://localhost:' + C.port + '/' + C.store.adminPath);
  console.log('🕐  Server time       | ' + now + ' (' + tz + ')');
  console.log('🔒  Security          | Session: ON · Rate-limit: ON · TRX entropy: ON');
  console.log('⚡  Compression       | gzip ON · Body limit: 256kb');
  console.log('🗃️  Database          | ' + _dbStatus);
  console.log('📦  CDN               | ' + _cdnStatus);

  if (!process.env.TOKEN_SECRET) console.warn('⚠️  TOKEN_SECRET tidak diset — token tidak persist antar restart. WAJIB diset di production!');
  if (!process.env.ADMIN_PASS)   console.error('🚨  [SECURITY] ADMIN_PASS tidak diset! Wajib set di environment variable untuk production.');
  if (DB_BACKEND === 'dongtube-external') {
    if (!process.env.DTDB_URL)     console.error('🚨  [DB-EXT] DTDB_URL tidak diset! Tambahkan di .env');
    if (!process.env.DTDB_API_KEY) console.error('🚨  [DB-EXT] DTDB_API_KEY tidak diset! Tambahkan di .env');
  }

  console.log('─────────────────────────────────────────────────────────');

  const server = app.listen(C.port, function() {
    console.log('✅  Server aktif      | http://localhost:' + C.port);
  });

  process.on('uncaughtException', function(err) {
    console.error('[CRASH PREVENTED] uncaughtException:', err.message);
  });
  process.on('unhandledRejection', function(reason) {
    console.error('[CRASH PREVENTED] unhandledRejection:', reason && reason.message ? reason.message : String(reason));
  });

  // ── Graceful shutdown ─────────────────────────────────────────────────────
  function _gracefulShutdown(signal) {
    console.log('[shutdown] ' + signal + ' diterima — menutup server...');
    // BUG FIX: Simpan data DB sebelum exit (db-local tidak lagi punya handler sendiri
    // untuk menghindari race condition — process.exit dipanggil di sini saja)
    try {
      const _dbMod = require('./lib/db-local');
      if (typeof _dbMod._saveAllData === 'function') _dbMod._saveAllData(signal);
    } catch(e) { /* db-external atau module belum load — skip */ }
    server.close(function() {
      console.log('[shutdown] HTTP server ditutup. Proses selesai.');
      process.exit(0);
    });
    setTimeout(function() {
      console.error('[shutdown] Forced exit setelah 10 detik.');
      process.exit(1);
    }, 10000);
  }
  process.on('SIGTERM', function() { _gracefulShutdown('SIGTERM'); });
  process.on('SIGINT',  function() { _gracefulShutdown('SIGINT'); });

  // ── Event-driven recovery: re-register semua pending item setelah restart ──
  // Menggantikan cron global — setiap item punya background watcher sendiri
  require('./lib/event-trigger').recoverOnStartup();

  setTimeout(function() {
    console.log('[startup] server ready.');
  }, 3000);
}


module.exports = app;
