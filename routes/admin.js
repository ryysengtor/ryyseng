'use strict';

const express = require('express');
const axios   = require('axios');
const router  = express.Router();
const crypto  = require('crypto');
const moment  = require('moment-timezone');

const C        = require('../lib/config');
const { RUNTIME, DATA_DIR: _DATA_DIR } = require('../lib/env-detect');
const { rateLimit, adminAuth, makeAdminToken } = require('../lib/auth');
const { dbRead, dbWrite, dbDelete, listDirCached, DB_BACKEND, _gitTreeCache, _dbCacheInvalidate } = require('../lib/db');
const {
  getProducts, getAccounts, saveAccounts, getSettings, getPanelTemplates, getEffectiveSettings,
  getTrx, saveTrx, listTrx, getUser, saveUser, listUsers,
  getDeposit, saveDeposit,
  getOtpOrder, listOtpOrders, getReviews, saveReviews, getChatMessages, saveChatMessages,
  getRsServer, saveRsServer, auditLog, updateBalance,
  isValidId, isValidUsername, hashPassword, _sleep, newId, invalidateAnalyticsCache,
} = require('../lib/models');
const { broadcastStore, broadcastAdmin, _feedBuf, _adminClients, _storeClients, getWebhookConfig, formatWebhookPayload } = require('../lib/broadcast');
const { ptH, SPEC, sanitizeUsername, createPanelServer } = require('../lib/panel');
const { _cdnAccounts, _cdnFolderCache, _cdnInvalidateCache } = require('../lib/cdn');
const { pgw, PAYMENT_GW, _pgwConfigured } = require('../lib/payment');
const rotp = require('../lib/rotp');
const { getLogs } = require('../lib/logger');
const eventTrigger = require('../lib/event-trigger');
const {
  triggerTrxWatch, triggerOtpOrderWatch,
  reconcileAllPendingDeposits, runLazyDepositCleanup,
} = require('../lib/event-trigger');

// ── Helper: sanitize product/variant IDs untuk path DB ────────────────────
function _sanitizeId(id) {
  if (!id || typeof id !== 'string') return null;
  var s = id.replace(/[^a-zA-Z0-9_\-]/g, '').slice(0, 64);
  return s || null;
}

router.post('/api/admin/login', function(req, res) {
  const ip   = req.ip || 'x';
  const pass = req.body.password || '';
  if (!rateLimit('login:' + ip, 5, 15 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.' });
  if (!pass || pass.length > 200) return res.json({ ok: false, message: 'Password salah.' });
  if (!process.env.ADMIN_PASS || C.store.adminPass === 'admin123') {
    console.error('[SECURITY CRITICAL] Login admin DIBLOKIR! ADMIN_PASS belum diset.');
    return res.status(503).json({ ok: false, message: 'Panel admin tidak dapat diakses: ADMIN_PASS belum dikonfigurasi. Hubungi owner server.' });
  }
  const _passBuf  = Buffer.from(pass);
  const _adminBuf = Buffer.from(C.store.adminPass);
  const passOk = _passBuf.length === _adminBuf.length && crypto.timingSafeEqual(_passBuf, _adminBuf);
  if (!passOk) { console.warn('[admin] login gagal dari', ip); return res.json({ ok: false, message: 'Password salah.' }); }
  const token = makeAdminToken();
  auditLog('login', 'Admin login dari ' + ip, ip).catch(function(){});
  res.json({ ok: true, token });
});
router.post('/api/admin/logout', function(req, res) { res.json({ ok: true }); });

router.get('/api/admin/diag', adminAuth, function(req, res) {
  var C = require('../lib/config');
  function _masked(val) { if (!val) return '❌ TIDAK ADA'; var s = String(val); return '✅ ADA (' + s.slice(0,4) + '****' + s.slice(-2) + ', ' + s.length + ' karakter)'; }
  function _bool(val) { return val ? '✅ ADA' : '❌ TIDAK ADA'; }
  res.json({
    ok: true,
    env: {
      NODE_ENV       : process.env.NODE_ENV || '(tidak diset)',
      RUMAHOTP_APIKEY: _masked(process.env.RUMAHOTP_APIKEY),
      ADMIN_PASS     : process.env.ADMIN_PASS && process.env.ADMIN_PASS !== 'admin123' ? '✅ ADA (custom)' : '⚠️ Default/tidak diset',
      DATABASE       : 'DongtubeDB (Local · WAL · ACID)',
      DATA_DIR       : _DATA_DIR + '  [' + RUNTIME.label + ']',
      TOKEN_SECRET   : _bool(process.env.TOKEN_SECRET),
    },
    config: {
      rotpApiKeyLoaded: !!C.otp.apikey,
      rotpBaseUrl     : require('../lib/rotp').baseUrl || 'https://www.rumahotp.io',
    }
  });
});

const { verifyToken } = require('../lib/auth');
function _sseSend(res, data) {
  if (res.writableEnded) return false;
  try { res.write('data: ' + JSON.stringify(data) + '\n\n'); if (typeof res.flush === 'function') res.flush(); return true; }
  catch(e) { return false; }
}
router.get('/api/store/stream', function(req, res) {
  res.setHeader('Content-Type', 'text/event-stream'); res.setHeader('Cache-Control', 'no-cache, no-store'); res.setHeader('Connection', 'keep-alive'); res.setHeader('X-Accel-Buffering', 'no'); res.setHeader('Access-Control-Allow-Origin', '*'); res.flushHeaders();
  _sseSend(res, { type: 'connected' }); _storeClients.add(res);
  var IS_VERCEL = !!process.env.VERCEL;
  var MAX_DURATION = IS_VERCEL ? 8000 : 55000;
  var startedAt = Date.now();
  var ping = setInterval(function() {
    if (Date.now() - startedAt > MAX_DURATION) { _sseSend(res, { type: 'reconnect' }); clearInterval(ping); _storeClients.delete(res); res.end(); return; }
    if (!_sseSend(res, { type: 'ping' })) { clearInterval(ping); _storeClients.delete(res); }
  }, 20000);
  req.on('close', function() { clearInterval(ping); _storeClients.delete(res); });
});
router.get('/api/admin/stream', function(req, res) {
  var token = req.query.t || req.headers['x-admin-token'];
  var payload = verifyToken(token);
  if (!payload || payload.role !== 'admin') { res.status(401).end(); return; }
  res.setHeader('Content-Type', 'text/event-stream'); res.setHeader('Cache-Control', 'no-cache'); res.setHeader('Connection', 'keep-alive'); res.setHeader('X-Accel-Buffering', 'no'); res.flushHeaders();
  _sseSend(res, { type: 'connected', ts: Date.now() }); _adminClients.add(res);
  var IS_VERCEL = !!process.env.VERCEL;
  var MAX_DURATION = IS_VERCEL ? 8000 : 55000;
  var startedAt = Date.now();
  var ping = setInterval(function() {
    if (Date.now() - startedAt > MAX_DURATION) { _sseSend(res, { type: 'reconnect' }); clearInterval(ping); _adminClients.delete(res); res.end(); return; }
    if (!_sseSend(res, { type: 'ping' })) { clearInterval(ping); _adminClients.delete(res); }
  }, 20000);
  req.on('close', function() { clearInterval(ping); _adminClients.delete(res); });
});
router.post('/api/admin/broadcast', adminAuth, function(req, res) {
  var ALLOWED_TYPES = ['reload', 'announcement', 'maintenance', 'settings_update'];
  var type = ALLOWED_TYPES.includes(req.body.type) ? req.body.type : 'reload';
  var msg  = String(req.body.msg || '').slice(0, 500).replace(/</g, '&lt;').replace(/>/g, '&gt;');
  broadcastStore({ type, msg });
  res.json({ ok: true, clients: _storeClients.size });
});

router.get('/api/admin/transactions', adminAuth, async function(req, res) {
  try {
    const files = await listTrx(); const results = [];
    await Promise.all(files.filter(function(f) { return f.name.endsWith('.json'); }).sort(function(a, b) { return b.name.localeCompare(a.name); }).slice(0, 200).map(async function(f) {
      try { const r = await dbRead('transactions/' + f.name, true); if (r.data) { const d = Object.assign({}, r.data); delete d.qrBase64; delete d.pakData; results.push(d); } } catch(e) {}
    }));
    results.sort(function(a, b) { return (b.createdAt || 0) - (a.createdAt || 0); });
    res.set('Cache-Control', 'no-store'); res.json({ ok: true, data: results, total: results.length });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.get('/api/admin/transactions/:id', adminAuth, async function(req, res) {
  try { const r = await getTrx(req.params.id); if (!r.data) return res.json({ ok: false, message: 'Tidak ditemukan.' }); const d = Object.assign({}, r.data); delete d.qrBase64; delete d.pakData; res.json({ ok: true, data: d }); }
  catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/transactions/:id/status', adminAuth, async function(req, res) {
  try {
    const id = req.params.id; const status = req.body.status; const note = String(req.body.note || '').slice(0, 500);
    const VALID = ['COMPLETED', 'PENDING', 'FAILED', 'EXPIRED', 'PAID_ERROR'];
    if (!VALID.includes(status)) return res.json({ ok: false, message: 'Status tidak valid.' });
    if (!isValidId(id)) return res.json({ ok: false, message: 'ID tidak valid.' });
    const r = await getTrx(id); if (!r.data) return res.json({ ok: false, message: 'Tidak ditemukan.' });
    await saveTrx(id, Object.assign({}, r.data, { status, adminNote: note, updatedAt: Date.now() }), r.sha);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.delete('/api/admin/transactions/:id', adminAuth, async function(req, res) {
  try {
    const id = req.params.id;
    if (!isValidId(id)) return res.json({ ok: false, message: 'ID tidak valid.' });
    const r = await getTrx(id); if (!r.data) return res.json({ ok: false, message: 'Tidak ditemukan.' });
    await dbDelete('transactions/' + id + '.json'); _gitTreeCache.delete('transactions');
    auditLog('delete-trx', id, req.adminIp).catch(function(){}); res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.delete('/api/admin/transactions', adminAuth, async function(req, res) {
  try {
    const files = await listTrx(); const jsons = files.filter(function(f){ return f.name.endsWith('.json'); });
    if (!jsons.length) return res.json({ ok: true, deleted: 0 });
    let deleted = 0, errors = 0;
    for (const f of jsons) { try { await dbDelete('transactions/' + f.name); _dbCacheInvalidate('transactions/' + f.name); _gitTreeCache.delete('transactions'); deleted++; } catch(e) { errors++; } }
    auditLog('reset-all-trx', 'deleted:' + deleted + ' errors:' + errors, req.adminIp).catch(function(){});
    res.json({ ok: true, deleted, errors });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.get('/api/admin/stats', adminAuth, async function(req, res) {
  try {
    const files = await listTrx(); let total = 0, pending = 0, completed = 0, failed = 0, revenue = 0;
    await Promise.all(files.filter(function(f) { return f.name.endsWith('.json'); }).map(async function(f) {
      try { const r = await dbRead('transactions/' + f.name); if (!r.data) return; total++; if (r.data.status === 'COMPLETED') { completed++; revenue += (r.data.totalBayar || r.data.unitPrice || 0); } else if (r.data.status === 'PENDING' || r.data.status === 'PAID') pending++; else failed++; } catch(e) {}
    }));
    res.json({ ok: true, total, pending, completed, failed, revenue });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});

router.get('/api/admin/init', adminAuth, async function(req, res) {
  try { const [prod, sett, templates] = await Promise.all([dbRead('products.json'), getEffectiveSettings(), getPanelTemplates()]); res.json({ ok: true, products: prod.data || [], settings: sett, templates }); }
  catch(e) { res.json({ ok: false, message: e.message }); }
});
router.get('/api/admin/products', adminAuth, async function(req, res) {
  try { const r = await dbRead('products.json'); res.json({ ok: true, data: r.data || [] }); } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.put('/api/admin/products', adminAuth, async function(req, res) {
  try {
    const products = Array.isArray(req.body) ? req.body : req.body.products;
    if (!Array.isArray(products)) return res.json({ ok: false, message: 'products harus array.' });
    const r = await dbRead('products.json', true);
    await dbWrite('products.json', products, r.sha || null, 'admin: update products');
    broadcastStore({ type: 'reload' }); res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.get('/api/admin/accounts/:productId/:variantId', adminAuth, async function(req, res) {
  try { const _pid = _sanitizeId(req.params.productId); const _vid = _sanitizeId(req.params.variantId);
    if (!_pid || !_vid) return res.json({ ok: false, message: 'ID tidak valid.' });
    const r = await getAccounts(_pid, _vid); const list = (r.data && Array.isArray(r.data)) ? r.data : []; res.json({ ok: true, count: list.length, accounts: list }); }
  catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/accounts/:productId/:variantId', adminAuth, async function(req, res) {
  try {
    const productId = _sanitizeId(req.params.productId); const variantId = _sanitizeId(req.params.variantId);
    if (!productId || !variantId) return res.json({ ok: false, message: 'ID tidak valid.' });
    const raw = String(req.body.accounts || req.body.data || '');
    const newAccts = raw.split('\n').map(function(s){ return s.trim(); }).filter(Boolean);
    if (newAccts.length === 0) return res.json({ ok: false, message: 'Tidak ada akun valid.' });
    if (newAccts.length > 500) return res.json({ ok: false, message: 'Maksimal 500 akun sekaligus.' });
    const r = await getAccounts(productId, variantId); const existing = (r.data && Array.isArray(r.data)) ? r.data : []; const merged = existing.concat(newAccts);
    await require('../lib/models').saveAccounts(productId, variantId, merged, r.sha || null);
    try { const pr = await dbRead('products.json', true); if (pr.data) { const prods = pr.data; const pi = prods.findIndex(function(p){ return p.id === productId; }); if (pi >= 0) { const vi = prods[pi].variants ? prods[pi].variants.findIndex(function(v){ return v.id === variantId; }) : -1; if (vi >= 0) { prods[pi].variants[vi].stock = merged.length; await dbWrite('products.json', prods, pr.sha, 'account-stock-sync:' + variantId); } } } } catch(e) {}
    res.json({ ok: true, added: newAccts.length, total: merged.length });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.delete('/api/admin/accounts/:productId/:variantId', adminAuth, async function(req, res) {
  try {
    const productId = _sanitizeId(req.params.productId); const variantId = _sanitizeId(req.params.variantId);
    if (!productId || !variantId) return res.json({ ok: false, message: 'ID tidak valid.' });
    const r = await getAccounts(productId, variantId);
    await require('../lib/models').saveAccounts(productId, variantId, [], r.sha || null);
    try { const pr = await dbRead('products.json', true); if (pr.data) { const prods = pr.data; const pi = prods.findIndex(function(p){ return p.id === productId; }); if (pi >= 0) { const vi = prods[pi].variants ? prods[pi].variants.findIndex(function(v){ return v.id === variantId; }) : -1; if (vi >= 0) { prods[pi].variants[vi].stock = 0; await dbWrite('products.json', prods, pr.sha, 'account-stock-clear:' + variantId); } } } } catch(e) {}
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.delete('/api/admin/accounts/:productId/:variantId/:index', adminAuth, async function(req, res) {
  try {
    const productId = _sanitizeId(req.params.productId); const variantId = _sanitizeId(req.params.variantId); const idx = parseInt(req.params.index, 10);
    if (!productId || !variantId) return res.json({ ok: false, message: 'ID tidak valid.' });
    if (isNaN(idx) || idx < 0) return res.json({ ok: false, message: 'Index tidak valid.' });
    const r = await getAccounts(productId, variantId); const list = (r.data && Array.isArray(r.data)) ? r.data : [];
    if (idx >= list.length) return res.json({ ok: false, message: 'Index di luar batas.' });
    list.splice(idx, 1); await require('../lib/models').saveAccounts(productId, variantId, list, r.sha);
    try { const pr = await dbRead('products.json', true); if (pr.data) { const prods = pr.data; const pi = prods.findIndex(function(p){ return p.id === productId; }); if (pi >= 0) { const vi = prods[pi].variants ? prods[pi].variants.findIndex(function(v){ return v.id === variantId; }) : -1; if (vi >= 0) { prods[pi].variants[vi].stock = list.length; await dbWrite('products.json', prods, pr.sha, 'account-stock-del:' + variantId); } } } } catch(e) {}
    res.json({ ok: true, remaining: list.length });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});

router.get('/api/admin/settings', adminAuth, async function(req, res) {
  try { res.json({ ok: true, data: await getEffectiveSettings() }); } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/settings', adminAuth, async function(req, res) {
  try {
    var b = req.body;
    var storeName = String(b.storeName || '').trim().slice(0, 100); if (!storeName) return res.json({ ok: false, message: 'Nama toko tidak boleh kosong.' });
    var wa = String(b.wa || '').trim().slice(0, 200); var channelWa = String(b.channelWa || '').trim().slice(0, 500);
    var expiryMin = parseInt(b.expiryMin, 10) || C.store.expiry; if (expiryMin < 1 || expiryMin > 1440) return res.json({ ok: false, message: 'Expiry 1–1440 menit.' });
    var logoUrl = String(b.logoUrl || '').trim().slice(0, 500); var appLogoUrl = String(b.appLogoUrl || '').trim().slice(0, 500);
    var announcement = String(b.announcement || '').trim().slice(0, 500); var footerText = String(b.footerText || '').trim().slice(0, 300);
    var primaryColor = String(b.primaryColor || '').trim().slice(0, 20); var tiktok = String(b.tiktok || '').trim().slice(0, 200); var instagram = String(b.instagram || '').trim().slice(0, 200);
    var otpEnabled = b.otpEnabled !== 'false' && b.otpEnabled !== false; var panelEnabled = b.panelEnabled !== 'false' && b.panelEnabled !== false;
    var maintenanceMode = b.maintenanceMode === 'true' || b.maintenanceMode === true; var maintenanceMsg = String(b.maintenanceMsg || 'Sedang dalam maintenance.').trim().slice(0, 300);
    var musicUrl = String(b.musicUrl || '').trim().slice(0, 500); var musicEnabled = b.musicEnabled === true || b.musicEnabled === 'true';
    var captchaEnabled = b.captchaEnabled === true || b.captchaEnabled === 'true';
    var depositFeeType = ['flat','percent'].includes(String(b.depositFeeType)) ? String(b.depositFeeType) : 'flat';
    var depositFee = parseFloat(b.depositFee) || 0; var depositMin = parseInt(b.depositMin, 10) || 1000; var otpMarkup = Math.max(0, parseFloat(b.otpMarkup) || 0);
    var bgUrl = String(b.bgUrl || '').trim().slice(0, 500); var bgType = ['image','video'].includes(String(b.bgType)) ? String(b.bgType) : 'image'; var bgOpacity = Math.min(1, Math.max(0, parseFloat(b.bgOpacity) || 0.15));
    var phoneRequired = b.phoneRequired === true || b.phoneRequired === 'true'; var phoneEnabled = b.phoneEnabled !== false && b.phoneEnabled !== 'false';
    // BUG FIX: 'description' sebelumnya tidak pernah dibaca dari req.body maupun
    // disimpan ke settings.json, menyebabkan deskripsi toko selalu terhapus saat
    // admin simpan settings (getEffectiveSettings membaca s.description tapi tidak pernah tertulis).
    var description = String(b.description || '').trim().slice(0, 500);
    var customFields = [];
    if (Array.isArray(b.customFields)) { customFields = b.customFields.slice(0, 10).map(function(f) { return { id: String(f.id || ('cf-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6))), label: String(f.label || '').trim().slice(0, 80), type: ['text','number','email','tel','textarea'].includes(f.type) ? f.type : 'text', required: f.required === true || f.required === 'true', placeholder: String(f.placeholder || '').trim().slice(0, 100), forProduct: ['all','panel','digital','download','sewabot'].includes(f.forProduct) ? f.forProduct : 'all' }; }).filter(function(f){ return f.label; }); }
    const r = await dbRead('settings.json', true);
    await dbWrite('settings.json', { storeName, wa, channelWa, expiryMin, logoUrl, appLogoUrl, announcement, footerText, primaryColor, tiktok, instagram, description, otpEnabled, panelEnabled, maintenanceMode, maintenanceMsg, musicUrl, musicEnabled, captchaEnabled, depositFeeType, depositFee, depositMin, otpMarkup, bgUrl, bgType, bgOpacity, phoneRequired, phoneEnabled, customFields }, r.sha || null, 'admin: settings');
    broadcastStore({ type: maintenanceMode ? 'maintenance' : 'settings_update', on: maintenanceMode, msg: maintenanceMsg, settings: { storeName, wa, channelWa, logoUrl, announcement, footerText, primaryColor, bgUrl, bgType, bgOpacity: parseFloat(bgOpacity), otpEnabled, panelEnabled } });
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.get('/api/admin/slides', adminAuth, async function(req, res) { try { const r = await dbRead('slides.json'); res.json({ ok: true, data: r.data || [] }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.post('/api/admin/slides', adminAuth, async function(req, res) {
  try {
    let slides = Array.isArray(req.body) ? req.body : req.body.slides;
    if (typeof slides === 'string') { try { slides = JSON.parse(slides); } catch(e) { slides = null; } }
    if (!Array.isArray(slides)) return res.json({ ok: false, message: 'slides harus array.' });
    slides = slides.map(function(s) { return { title: String(s.title || '').slice(0, 200), desc: String(s.desc || '').slice(0, 500), tag: String(s.tag || '').slice(0, 80), image: (s.image && String(s.image).startsWith('http')) ? String(s.image).slice(0, 500) : '', img: (s.img && String(s.img).startsWith('http')) ? String(s.img).slice(0, 500) : '', btnText: String(s.btnText || '').slice(0, 80), btnCat: String(s.btnCat || '').replace(/[^a-z0-9_\-]/g,'').slice(0, 40) }; }).filter(function(s){ return s.title || s.desc; });
    const r = await dbRead('slides.json', true); await dbWrite('slides.json', slides, r.sha || null, 'admin: slides'); res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.get('/api/slides', async function(req, res) { try { const r = await dbRead('slides.json'); res.json({ ok: true, data: r.data || [] }); } catch(e) { res.json({ ok: true, data: [] }); } });

router.get('/api/admin/categories', adminAuth, async function(req, res) {
  try {
    const r = await dbRead('categories.json');
    res.json({ ok: true, data: r.data || [] });
  } catch(e) { res.json({ ok: true, data: [] }); }
});
router.post('/api/admin/categories', adminAuth, async function(req, res) {
  try {
    let cats = Array.isArray(req.body) ? req.body : req.body.categories;
    if (typeof cats === 'string') { try { cats = JSON.parse(cats); } catch(e) { cats = null; } }
    if (!Array.isArray(cats)) return res.json({ ok: false, message: 'categories harus array.' });
    cats = cats.filter(function(c) { return c && (c.name || c); }).map(function(c) {
      if (typeof c === 'string') return { id: 'cat-' + Date.now() + Math.random().toString(36).slice(2), name: c.trim() };
      return { id: c.id || ('cat-' + Date.now() + Math.random().toString(36).slice(2)), name: String(c.name || '').trim() };
    }).filter(function(c) { return c.name; });
    const r = await dbRead('categories.json', true);
    await dbWrite('categories.json', cats, r.sha || null, 'admin: update categories');
    broadcastStore({ type: 'reload' });
    res.json({ ok: true, data: cats });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});

router.post('/api/admin/seed-products', adminAuth, async function(req, res) {
  try {
    const { confirm: confirmed, merge } = req.body || {};
    if (!confirmed) return res.json({ ok: false, message: 'Konfirmasi diperlukan.' });
    const seedProducts = Object.keys(SPEC).map(function(id, i) {
      const spec = SPEC[id];
      const ramGb = id === 'unlimited' ? 'Unlimited' : id.replace('gb', '') + 'GB';
      const basePrice = id === 'unlimited' ? 150000 : parseInt(id.replace('gb', ''), 10) * 10000;
      return {
        id: 'panel-' + id,
        name: 'Panel ' + ramGb + ' RAM',
        category: 'Panel Hosting',
        type: 'panel',
        description: 'Panel hosting dengan RAM ' + ramGb + (spec.cpu ? ', CPU ' + spec.cpu + '%' : '') + (spec.disk ? ', Disk ' + Math.round(spec.disk / 1024) + 'GB' : ''),
        image: '',
        active: true,
        variants: [
          { id: 'v-' + id + '-30', name: '30 Hari', price: basePrice, stock: 999, active: true, duration: 30 },
          { id: 'v-' + id + '-60', name: '60 Hari', price: Math.round(basePrice * 1.8), stock: 999, active: true, duration: 60 },
          { id: 'v-' + id + '-90', name: '90 Hari', price: Math.round(basePrice * 2.5), stock: 999, active: true, duration: 90 },
        ],
        planId: id,
      };
    });
    const r = await dbRead('products.json', true);
    let final = seedProducts;
    if (merge && r.data && Array.isArray(r.data)) {
      const existingIds = new Set(r.data.map(function(p) { return p.id; }));
      const toAdd = seedProducts.filter(function(p) { return !existingIds.has(p.id); });
      final = r.data.concat(toAdd);
    }
    await dbWrite('products.json', final, r.sha || null, 'admin: seed panel products');
    broadcastStore({ type: 'reload' });
    res.json({ ok: true, message: final.length + ' produk tersimpan.', preview: seedProducts.map(function(p) { return { name: p.name, variants: p.variants.length }; }) });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});

router.get('/api/admin/panels', adminAuth, async function(req, res) {
  try {
    if (!C.ptero.domain || !C.ptero.apikey) return res.json({ ok: false, message: 'Pterodactyl belum dikonfigurasi.' });
    const sRes = await axios.get(C.ptero.domain + '/api/application/servers?per_page=100', { headers: ptH() });
    const servers = (sRes.data && sRes.data.data) ? sRes.data.data.map(function(s) {
      const srv = s.attributes;
      const lim = srv.limits || {};
      return {
        serverId  : srv.id,
        name      : srv.name,
        description: srv.description,
        suspended : !!srv.suspended,
        status    : srv.suspended ? 'suspended' : 'active',
        userId    : srv.user,
        username  : srv.name,
        ram       : lim.memory === 0 ? 'Unlimited' : (lim.memory / 1024).toFixed(1) + 'GB',
        disk      : lim.disk   === 0 ? 'Unlimited' : (lim.disk   / 1024).toFixed(1) + 'GB',
        cpu       : lim.cpu    === 0 ? 'Unlimited' : lim.cpu + '%',
        nodeId    : srv.node,
        eggId     : srv.egg,
        nestId    : srv.nest,
        createdAt : srv.created_at ? new Date(srv.created_at).getTime() : null,
      };
    }) : [];
    servers.sort(function(a, b) { return (b.createdAt || 0) - (a.createdAt || 0); });
    res.json({ ok: true, data: servers, total: servers.length });
  } catch(e) { res.json({ ok: false, message: 'Gagal koneksi Pterodactyl: ' + e.message }); }
});
router.post('/api/admin/panels/:sid/suspend', adminAuth, async function(req, res) { try { const sid = parseInt(req.params.sid, 10); if (!sid) return res.json({ ok: false, message: 'ID tidak valid.' }); const r = await axios.post(C.ptero.domain + '/api/application/servers/' + sid + '/suspend', {}, { headers: ptH() }); if (r.status === 204) res.json({ ok: true }); else res.json({ ok: false, message: 'Ptero: ' + r.status }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.post('/api/admin/panels/:sid/unsuspend', adminAuth, async function(req, res) { try { const sid = parseInt(req.params.sid, 10); if (!sid) return res.json({ ok: false, message: 'ID tidak valid.' }); const r = await axios.post(C.ptero.domain + '/api/application/servers/' + sid + '/unsuspend', {}, { headers: ptH() }); if (r.status === 204) res.json({ ok: true }); else res.json({ ok: false, message: 'Ptero: ' + r.status }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.post('/api/admin/panels/:sid/reinstall', adminAuth, async function(req, res) { try { const sid = parseInt(req.params.sid, 10); if (!sid) return res.json({ ok: false, message: 'Server ID tidak valid.' }); const r = await axios.post(C.ptero.domain + '/api/application/servers/' + sid + '/reinstall', {}, { headers: ptH() }); if (r.status === 204) { auditLog('reinstall', 'Server ' + sid, req.adminIp).catch(function(){}); res.json({ ok: true }); } else { res.json({ ok: false, message: 'Ptero: ' + r.status }); } } catch(e) { res.json({ ok: false, message: e.message }); } });
// Hapus reseller-server dari database (entry yang tidak ada di Pterodactyl)
router.delete('/api/admin/panels/db/:rsvId', adminAuth, async function(req, res) {
  try {
    const { getRsServer, saveRsServer } = require('../lib/models');
    const rsvId = req.params.rsvId;
    if (!rsvId) return res.json({ ok: false, message: 'RSV ID tidak valid.' });
    const r = await getRsServer(rsvId);
    if (!r || !r.data) return res.json({ ok: false, message: 'Data tidak ditemukan di database.' });
    await saveRsServer(rsvId, Object.assign({}, r.data, {
      status: 'deleted', _deletedFromDb: true, _deletedAt: Date.now(), _deletedBy: 'admin-db-cleanup'
    }), r.sha);
    auditLog('delete-db-orphan', 'RSV ' + rsvId + ' (server ' + (r.data.serverId || '?') + ')', req.adminIp).catch(function(){});
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/panels/:sid/extend', adminAuth, async function(req, res) {
  try {
    const serverId = parseInt(req.params.sid, 10); const addDays = parseInt(req.body.days, 10);
    if (!serverId || isNaN(addDays) || addDays < 1 || addDays > 3650) return res.json({ ok: false, message: 'Input tidak valid (1–3650 hari).' });
    const files = await listTrx(); let targetTrx = null, targetR = null;
    for (const f of files.filter(function(f) { return f.name.endsWith('.json'); })) { try { const r = await dbRead('transactions/' + f.name); if (r.data && r.data.result && String(r.data.result.serverId) === String(serverId)) { if (!targetTrx || (r.data.completedAt || 0) > (targetTrx.completedAt || 0)) { targetTrx = r.data; targetR = r; } } } catch(e) {} }
    if (!targetTrx) {
      try {
        const rsFiles = (await listDirCached('reseller-servers')).filter(function(f){ return f.name.endsWith('.json'); });
        for (const f of rsFiles) { try { const r = await getRsServer(f.name.replace('.json','')); if (r.data && String(r.data.serverId) === String(serverId) && r.data.status !== 'deleted') { const rsvId = r.data.id; const base = (r.data.expiresAt && r.data.expiresAt > Date.now()) ? r.data.expiresAt : Date.now(); const newExpiry = base + addDays * 86400000; try { const sRes = await axios.get(C.ptero.domain + '/api/application/servers/' + serverId, { headers: ptH() }); const srv = sRes.data.attributes; await axios.patch(C.ptero.domain + '/api/application/servers/' + serverId + '/details', { name: srv.name, user: srv.user, email: srv.user, external_id: srv.external_id || null, description: 'RS:' + r.data.resellerUsername + ' | exp: ' + new Date(newExpiry).toLocaleDateString('id-ID') + ' [admin+' + addDays + 'd]' }, { headers: ptH() }); } catch(e) {} const freshR = await getRsServer(rsvId); await saveRsServer(rsvId, Object.assign({}, freshR.data || r.data, { expiresAt: newExpiry, status: 'active', extendedAt: Date.now(), extendedDays: (r.data.extendedDays || 0) + addDays }), freshR.sha || r.sha); _gitTreeCache.delete('reseller-servers'); auditLog('extend-rs-via-panels', 'Server ' + serverId + ' rsvId:' + rsvId + ' +' + addDays + 'd', req.adminIp).catch(function(){}); return res.json({ ok: true, newExpiry, newExpiryFmt: new Date(newExpiry).toLocaleDateString('id-ID') }); } } catch(e) {} }
      } catch(e) {}
    }
    if (!targetTrx) {
      let ptSrv = null;
      try { const sRes = await axios.get(C.ptero.domain + '/api/application/servers/' + serverId, { headers: ptH() }); ptSrv = sRes.data.attributes; } catch(e) { return res.json({ ok: false, message: 'Panel tidak ditemukan di database maupun Pterodactyl.' }); }
      const syntheticId = newId('TRX');
      const syntheticTrx = { id: syntheticId, productType: 'panel', productName: 'Panel (auto-import)', variantName: ptSrv.name || ('Server ' + serverId), status: 'COMPLETED', completedAt: Date.now(), createdAt: Date.now(), _autoImported: true, result: { serverId, username: ptSrv.name || ('server' + serverId), userId: ptSrv.user || null, domain: C.ptero.domain, ram: ptSrv.limits ? (ptSrv.limits.memory / 1024).toFixed(1) + 'GB' : '?', disk: ptSrv.limits ? (ptSrv.limits.disk / 1024).toFixed(1) + 'GB' : '?', cpu: ptSrv.limits ? ptSrv.limits.cpu + '%' : '?', expiresAt: Date.now() } };
      await saveTrx(syntheticId, syntheticTrx, null); _gitTreeCache.delete('transactions');
      const freshSyn = await getTrx(syntheticId); targetTrx = freshSyn.data || syntheticTrx; targetR = freshSyn;
    }
    const base = (targetTrx.result.expiresAt && targetTrx.result.expiresAt > Date.now()) ? targetTrx.result.expiresAt : Date.now();
    const newExpiry = base + addDays * 86400000;
    try { const sRes = await axios.get(C.ptero.domain + '/api/application/servers/' + serverId, { headers: ptH() }); const srv = sRes.data.attributes; await axios.patch(C.ptero.domain + '/api/application/servers/' + serverId + '/details', { name: srv.name, user: srv.user, email: srv.user, external_id: srv.external_id || null, description: 'Dongtube ' + targetTrx.id + ' | exp: ' + new Date(newExpiry).toLocaleDateString('id-ID') + ' [admin+' + addDays + 'd]' }, { headers: ptH() }); } catch(e) {}
    const freshR2 = await getTrx(targetTrx.id);
    await saveTrx(targetTrx.id, Object.assign({}, freshR2.data || targetTrx, { result: Object.assign({}, targetTrx.result, { expiresAt: newExpiry }), renewedAt: Date.now(), adminExtended: ((freshR2.data || targetTrx).adminExtended || 0) + addDays }), freshR2.sha || (targetR && targetR.sha) || null);
    auditLog('extend', 'Server ' + serverId + ' +' + addDays + 'd', req.adminIp).catch(function(){});
    res.json({ ok: true, newExpiry, newExpiryFmt: new Date(newExpiry).toLocaleDateString('id-ID') });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/panels/:sid/reduce', adminAuth, async function(req, res) {
  try {
    const serverId = parseInt(req.params.sid, 10); const reduceDays = parseInt(req.body.days, 10);
    if (!serverId || isNaN(reduceDays) || reduceDays < 1 || reduceDays > 3650) return res.json({ ok: false, message: 'Input tidak valid (1–3650 hari).' });
    const files = await listTrx(); let targetTrx = null, targetR = null;
    for (const f of files.filter(function(f){ return f.name.endsWith('.json'); })) { try { const r = await dbRead('transactions/' + f.name); if (r.data && r.data.result && String(r.data.result.serverId) === String(serverId)) { if (!targetTrx || (r.data.completedAt||0) > (targetTrx.completedAt||0)) { targetTrx = r.data; targetR = r; } } } catch(e) {} }
    if (!targetTrx || !targetTrx.result) return res.json({ ok: false, message: 'Panel tidak ditemukan di database.' });
    const cur = (targetTrx.result.expiresAt && targetTrx.result.expiresAt > Date.now()) ? targetTrx.result.expiresAt : Date.now();
    const newExpiry = Math.max(Date.now(), cur - reduceDays * 86400000);
    try { const sRes = await axios.get(C.ptero.domain + '/api/application/servers/' + serverId, { headers: ptH() }); const srv = sRes.data.attributes; await axios.patch(C.ptero.domain + '/api/application/servers/' + serverId + '/details', { name: srv.name, user: srv.user, email: srv.user, external_id: srv.external_id || null, description: 'Dongtube ' + targetTrx.id + ' | exp: ' + new Date(newExpiry).toLocaleDateString('id-ID') + ' [admin-' + reduceDays + 'd]' }, { headers: ptH() }); } catch(e) {}
    const fr2 = await getTrx(targetTrx.id);
    await saveTrx(targetTrx.id, Object.assign({}, fr2.data||targetTrx, { result: Object.assign({}, targetTrx.result, { expiresAt: newExpiry }), reducedAt: Date.now(), adminReduced: ((fr2.data||targetTrx).adminReduced||0) + reduceDays }), fr2.sha || (targetR && targetR.sha) || null);
    auditLog('reduce', 'Server ' + serverId + ' -' + reduceDays + 'd', req.adminIp).catch(function(){});
    res.json({ ok: true, newExpiry, newExpiryFmt: new Date(newExpiry).toLocaleDateString('id-ID') });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.delete('/api/admin/panels/:sid', adminAuth, async function(req, res) {
  try {
    const sid = parseInt(req.params.sid, 10); if (!sid) return res.json({ ok: false, message: 'ID tidak valid.' });
    const headers = ptH(); const domain = C.ptero.domain; let srvDeleted = false;
    try { await axios.delete(domain + '/api/application/servers/' + sid, { headers }); srvDeleted = true; } catch(e) { if (e.response && e.response.status === 404) srvDeleted = true; }
    const files = await listTrx(); let ptUid = null, tTrxId = null, tR = null;
    for (const f of files.filter(function(f) { return f.name.endsWith('.json'); })) { try { const r = await dbRead('transactions/' + f.name); if (r.data && r.data.result && String(r.data.result.serverId) === String(sid)) { ptUid = r.data.result.userId; tTrxId = r.data.id; tR = r; if (ptUid) break; } } catch(e) {} }
    if (ptUid) { try { await axios.delete(domain + '/api/application/users/' + ptUid, { headers }); } catch(e) {} }
    if (tTrxId && tR && tR.data) await saveTrx(tTrxId, Object.assign({}, tR.data, { status: 'EXPIRED', _panelDeleted: true, _deletedAt: Date.now(), _deletedBy: 'admin' }), tR.sha);
    auditLog('delete-panel', 'Server ' + sid, req.adminIp).catch(function(e) {});
    res.json({ ok: true, srvDeleted });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/panels/:sid/reset-password', adminAuth, async function(req, res) {
  try {
    const sid = parseInt(req.params.sid, 10); const newPwd = String(req.body.password || '').trim();
    if (!sid) return res.json({ ok: false, message: 'Server ID tidak valid.' });
    if (!newPwd || newPwd.length < 6 || newPwd.length > 72) return res.json({ ok: false, message: 'Password minimal 6, maksimal 72 karakter.' });
    const SAFE_PASS = /^[a-zA-Z0-9!@#$%^&*_+=.-]+$/; if (!SAFE_PASS.test(newPwd)) return res.json({ ok: false, message: 'Password mengandung karakter tidak valid.' });
    const files = await listTrx(); let ptUserId = null; let uname = null;
    for (const f of files.filter(function(f) { return f.name.endsWith('.json'); })) { try { const r = await dbRead('transactions/' + f.name); if (r.data && r.data.result && String(r.data.result.serverId) === String(sid)) { ptUserId = r.data.result.userId; uname = r.data.result.username; break; } } catch(e) {} }
    if (!ptUserId) return res.json({ ok: false, message: 'User ID tidak ditemukan di DB.' });
    await axios.patch(C.ptero.domain + '/api/application/users/' + ptUserId, { email: (uname || 'user') + '@Dongtube.local', username: uname || ('user' + ptUserId), first_name: uname || 'User', last_name: 'Panel', password: newPwd, language: 'en' }, { headers: ptH() });
    for (const f of files.filter(function(f) { return f.name.endsWith('.json'); })) { try { const r = await dbRead('transactions/' + f.name); if (r.data && r.data.result && String(r.data.result.serverId) === String(sid)) { await saveTrx(r.data.id, Object.assign({}, r.data, { result: Object.assign({}, r.data.result, { password: newPwd }), panelPassword: newPwd, _pwResetAt: Date.now(), _pwResetBy: 'admin' }), r.sha); break; } } catch(e) {} }
    auditLog('reset-password', 'Server ' + sid, req.adminIp).catch(function(){});
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/panels/run-cron', adminAuth, async function(req, res) {
  res.json({ ok: true, message: 'Auto-suspend panel telah dinonaktifkan.' });
});

router.get('/api/admin/users', adminAuth, async function(req, res) {
  try {
    const files = await listUsers(); const users = [];
    await Promise.all(files.filter(function(f){ return f.name.endsWith('.json'); }).map(async function(f) { try { const r = await getUser(f.name.replace('.json','')); if (r.data) users.push({ username: r.data.username, balance: r.data.balance||0, email: r.data.email, banned: r.data.banned||false, createdAt: r.data.createdAt, lastLogin: r.data.lastLogin }); } catch(e) {} }));
    users.sort(function(a,b){ return (b.createdAt||0)-(a.createdAt||0); }); res.json({ ok: true, data: users });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/users/:username/balance', adminAuth, async function(req, res) {
  try {
    const username = req.params.username; if (!isValidUsername(username)) return res.json({ ok: false, message: 'Username tidak valid.' });
    const delta = parseInt(req.body.delta, 10); if (isNaN(delta) || delta === 0) return res.json({ ok: false, message: 'Jumlah tidak valid.' });
    if (Math.abs(delta) > 100000000) return res.json({ ok: false, message: 'Delta terlalu besar.' });
    const newBal = await updateBalance(username, delta);
    auditLog('adjust-balance', username + ' delta:' + delta + ' newbal:' + newBal, req.adminIp).catch(function(){});
    res.json({ ok: true, newBalance: newBal });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/users/:username/ban', adminAuth, async function(req, res) {
  try {
    const username = req.params.username; const ban = req.body.ban !== false && req.body.ban !== 'false';
    if (!isValidUsername(username)) return res.json({ ok: false, message: 'Username tidak valid.' });
    const r = await getUser(username); if (!r.data) return res.json({ ok: false, message: 'User tidak ditemukan.' });
    await saveUser(username, Object.assign({}, r.data, { banned: ban }), r.sha);
    auditLog(ban ? 'ban-user' : 'unban-user', username, req.adminIp).catch(function(){});
    if (ban) broadcastStore({ type: 'user_banned', username });
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/users/:username/reset-password', adminAuth, async function(req, res) {
  try {
    const username = req.params.username; const newPwd = String(req.body.password || '').trim();
    if (!isValidUsername(username)) return res.json({ ok: false, message: 'Username tidak valid.' });
    if (!newPwd || newPwd.length < 6) return res.json({ ok: false, message: 'Password minimal 6 karakter.' });
    const r = await getUser(username); if (!r.data) return res.json({ ok: false, message: 'User tidak ditemukan.' });
    const hashed = await hashPassword(newPwd);
    await saveUser(username, Object.assign({}, r.data, { passwordHash: hashed, updatedAt: Date.now(), lastTokenReset: Date.now() }), r.sha);
    auditLog('reset-user-pwd', username, req.adminIp).catch(function(){}); res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});

router.get('/api/admin/otp/balance', adminAuth, async function(req, res) { try { const r = await rotp.balance(); res.json({ ok: r.success, data: r.data || {} }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.get('/api/admin/otp/orders', adminAuth, async function(req, res) {
  try {
    let all = []; try { const r = await listDirCached('otp-orders'); const files = Array.isArray(r) ? r.filter(function(f){ return f.name.endsWith('.json'); }) : []; await Promise.all(files.map(async function(f) { try { const d = await getOtpOrder(f.name.replace('.json','')); if(d.data) all.push(d.data); } catch(e) {} })); } catch(e) {}
    all.sort(function(a,b){ return (b.createdAt||0)-(a.createdAt||0); }); res.json({ ok: true, data: all.slice(0,100) });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/otp/run-expire', adminAuth, async function(req, res) {
  (async function() {
    try {
      const { listDirCached: ldc2, getOtpOrder } = require('../lib/models');
      const files = (await ldc2('otp-orders')).filter(function(f){ return f.name.endsWith('.json'); });
      for (const f of files) {
        try {
          const d = await getOtpOrder(f.name.replace('.json',''));
          if (!d || !d.data) continue;
          const s = d.data.status;
          if (s === 'waiting' || s === 'expiring' || s === 'canceling') {
            triggerOtpOrderWatch(d.data.id);
          }
        } catch(e) {}
      }
    } catch(e) { console.warn('[admin/otp/run-expire]', e.message); }
  })().catch(function(){});
  res.json({ ok: true, message: 'OTP expire scan dijadwalkan.' });
});
router.get('/api/admin/otp/pinned', adminAuth, async function(req, res) { try { const r = await dbRead('otp-pinned.json'); res.json({ ok: true, data: r.data || [] }); } catch(e) { res.json({ ok: true, data: [] }); } });
router.post('/api/admin/otp/pinned', adminAuth, async function(req, res) { try { var codes = req.body; if (!Array.isArray(codes)) return res.json({ ok: false, message: 'Data harus array.' }); codes = codes.filter(function(c){ return typeof c === 'string' && c.length < 100; }).slice(0, 50); const r = await dbRead('otp-pinned.json', true); await dbWrite('otp-pinned.json', codes, r.sha || null, 'admin: otp-pinned'); res.json({ ok: true }); } catch(e) { res.json({ ok: false, message: e.message }); } });

router.get('/api/admin/feed', adminAuth, async function(req, res) { try { var memBuf = _feedBuf.slice(); var dbBuf = []; try { const r = await dbRead('feed-cache.json'); if (Array.isArray(r.data)) dbBuf = r.data; } catch(e) {} res.json({ ok: true, inMemoryCount: memBuf.length, dbCacheCount: dbBuf.length, data: dbBuf }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.delete('/api/admin/feed', adminAuth, async function(req, res) { try { _feedBuf.length = 0; const r = await dbRead('feed-cache.json', true); if (r.sha) await dbWrite('feed-cache.json', [], r.sha, 'admin: clear feed cache'); auditLog('clear-feed', 'Feed cache dihapus', req.adminIp).catch(function(){}); res.json({ ok: true, message: 'Feed cache berhasil direset.' }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.get('/api/admin/webhook', adminAuth, async function(req, res) { try { const r = await dbRead('webhook-config.json'); res.json({ ok: true, data: r.data || { url: '', secret: '', enabled: false } }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.post('/api/admin/webhook', adminAuth, async function(req, res) {
  try {
    var url = String(req.body.url || '').trim().slice(0, 500); var secret = String(req.body.secret || '').trim().slice(0, 200); var enabled = req.body.enabled !== false && req.body.enabled !== 'false';
    if (url) { if (!url.startsWith('http://') && !url.startsWith('https://')) return res.json({ ok: false, message: 'URL harus dimulai dengan https://' }); const _ssrfBlock = /^https?:\/\/(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|::1|metadata\.|fd[0-9a-f]{2}:)/i; if (_ssrfBlock.test(url)) return res.json({ ok: false, message: 'URL tidak diizinkan.' }); }
    const r = await dbRead('webhook-config.json', true); await dbWrite('webhook-config.json', { url, secret, enabled }, r.sha || null, 'admin: webhook');
    require('../lib/broadcast')._webhookCache = { url, secret, enabled };
    auditLog('webhook-update', url, req.adminIp).catch(function(){}); res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/webhook/test', adminAuth, async function(req, res) {
  try {
    const cfg = await getWebhookConfig(); if (!cfg || !cfg.url) return res.json({ ok: false, message: 'URL webhook belum dikonfigurasi.' }); if (cfg.enabled === false) return res.json({ ok: false, message: 'Webhook tidak aktif.' });
    const testPayload = formatWebhookPayload({ id: 'TEST-' + Date.now(), type: 'order', ts: Date.now(), label: 'Test — Produk Contoh (Panel 1GB)', amount: 25000, productName: 'Hosting Panel', variantName: '1GB / 30 Hari', productType: 'panel', phone: '628123456789' });
    await axios.post(cfg.url, testPayload, { timeout: 8000, headers: { 'Content-Type': 'application/json', 'X-Dongtube-Event': 'test', 'X-Dongtube-Secret': cfg.secret || '' } });
    res.json({ ok: true, message: 'Test berhasil dikirim ke webhook.', payload: testPayload });
  } catch(e) { res.json({ ok: false, message: 'Gagal: ' + e.message }); }
});

router.get('/api/admin/system-info', adminAuth, function(req, res) {
  var dbInfo = { backend: 'dongtubedb', engine: 'WowoEngine', wal: true, acid: true, ready: true };
  var cdnAccs = _cdnAccounts();
  var envHint = [
    'NODE_ENV=' + (process.env.NODE_ENV || 'production'),
    'DB_MODE=' + (process.env.DB_MODE || 'local'),
    'PORT=' + (process.env.PORT || '3000'),
  ].join(' | ');
  res.json({ ok: true, version: '2.0.0', db: dbInfo, cdn: cdnAccs.map(function(a){ return { name: a.name, owner: a.owner, repos: a.repos }; }), ptero: { configured: !!(C.ptero.domain && C.ptero.apikey), domain: C.ptero.domain }, payment: { gateway: PAYMENT_GW, configured: _pgwConfigured() }, store: { name: C.store.name }, env_hint: envHint });
});
router.get('/api/admin/server-log', adminAuth, function(req, res) {
  try { var limit = Math.min(parseInt(req.query.limit, 10) || 100, 500); var level = req.query.level || 'all'; var logs = getLogs(); if (level !== 'all') logs = logs.filter(function(l){ return l.level === level; }); res.json({ ok: true, data: logs.slice(-limit).reverse() }); }
  catch(e) { res.json({ ok: false, message: e.message }); }
});
router.get('/api/admin/server-metrics', adminAuth, function(req, res) {
  try { var os = require('os'); var mem = process.memoryUsage(); var load = os.loadavg(); var cpus = os.cpus(); var totalMem = os.totalmem(); var freeMem = os.freemem(); res.json({ ok: true, data: { uptime_process: Math.floor(process.uptime()), uptime_system: Math.floor(os.uptime()), load_avg: load, cpu_count: cpus.length, cpu_model: cpus[0] && cpus[0].model, mem_total: totalMem, mem_free: freeMem, mem_used: totalMem - freeMem, mem_percent: Math.round((totalMem - freeMem) / totalMem * 100), process_heap_used: mem.heapUsed, process_heap_total: mem.heapTotal, process_rss: mem.rss, node_version: process.version, platform: os.platform(), arch: os.arch(), hostname: os.hostname() } }); }
  catch(e) { res.json({ ok: false, message: e.message }); }
});
router.get('/api/admin/audit', adminAuth, async function(req, res) { try { const r = await dbRead('audit.json'); res.json({ ok: true, data: Array.isArray(r.data) ? r.data.slice(0, 100) : [] }); } catch(e) { res.json({ ok: false, message: e.message }); } });


// ─── Admin Pterodactyl Live Data ─────────────────────────────────────────────

router.get('/api/admin/ptero/locations', adminAuth, async function(req, res) {
  try {
    const { ptCfg } = require('../lib/panel');
    const r = await axios.get(C.ptero.domain + '/api/application/locations?per_page=100', ptCfg());
    const locs = (r.data && r.data.data) ? r.data.data.map(function(l) {
      return { id: l.attributes.id, short: l.attributes.short, long: l.attributes.long };
    }) : [];
    res.json({ ok: true, data: locs });
  } catch(e) { res.json({ ok: false, message: e.message, data: [] }); }
});

router.get('/api/admin/ptero/nests', adminAuth, async function(req, res) {
  try {
    const { getPteroNests } = require('../lib/panel');
    const nests = await getPteroNests();
    res.json({ ok: true, data: nests });
  } catch(e) { res.json({ ok: false, message: e.message, data: [] }); }
});

router.get('/api/admin/ptero/nests/:nestId/eggs', adminAuth, async function(req, res) {
  try {
    const { getPteroEggsForNest } = require('../lib/panel');
    const eggs = await getPteroEggsForNest(parseInt(req.params.nestId, 10));
    res.json({ ok: true, data: eggs });
  } catch(e) { res.json({ ok: false, message: e.message, data: [] }); }
});

router.get('/api/admin/ptero/eggs/:nestId/:eggId', adminAuth, async function(req, res) {
  try {
    const { getEggDetail } = require('../lib/panel');
    const egg = await getEggDetail(parseInt(req.params.nestId, 10), parseInt(req.params.eggId, 10));
    res.json({ ok: true, data: egg });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});

router.get('/api/admin/panel-templates', adminAuth, async function(req, res) {
  try {
    const templates = await getPanelTemplates();
    const defaultPlans = Object.keys(SPEC).map(function(id) { const t = templates.find(function(x){ return x.id === id; }); if (t) return t; return { id, name: id.toUpperCase(), active: true, ram: SPEC[id].ram, disk: SPEC[id].disk, cpu: SPEC[id].cpu, io: 500, swap: 0, egg: C.ptero.egg, nest: C.ptero.nest, location: C.ptero.location, docker_image: 'ghcr.io/parkervcp/yolks:nodejs_20', startup: '', environment: { INST: 'npm', USER_UPLOAD: '0', AUTO_UPDATE: '0', CMD_RUN: 'npm start' }, feature_limits: { databases: 5, backups: 5, allocations: 5 } }; });
    var merged = defaultPlans.slice(); templates.forEach(function(t) { var idx = merged.findIndex(function(x){ return x.id === t.id; }); if (idx >= 0) merged[idx] = t; else merged.push(t); });
    res.json({ ok: true, data: merged, ptero: { domain: C.ptero.domain, egg: C.ptero.egg, nest: C.ptero.nest, location: C.ptero.location } });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/panel-templates', adminAuth, async function(req, res) {
  try {
    const templates = Array.isArray(req.body) ? req.body : req.body.templates; if (!Array.isArray(templates)) return res.json({ ok: false, message: 'templates harus array.' });
    const clean = templates.map(function(t) { return { id: String(t.id || '').toLowerCase().replace(/[^a-z0-9_]/g,'').slice(0,20), name: String(t.name || t.id || '').slice(0,50), active: t.active !== false, ram: parseInt(t.ram, 10) || 0, disk: parseInt(t.disk, 10) || 0, cpu: parseInt(t.cpu, 10) || 0, io: parseInt(t.io, 10) || 500, swap: parseInt(t.swap, 10) || 0, egg: parseInt(t.egg, 10) || C.ptero.egg, nest: parseInt(t.nest, 10) || C.ptero.nest, location: parseInt(t.location, 10) || C.ptero.location, docker_image: String(t.docker_image || 'ghcr.io/parkervcp/yolks:nodejs_20').slice(0,200), startup: String(t.startup || '').slice(0,1000), environment: (t.environment && typeof t.environment === 'object') ? t.environment : { INST: 'npm', USER_UPLOAD: '0', AUTO_UPDATE: '0', CMD_RUN: 'npm start' }, feature_limits: (t.feature_limits && typeof t.feature_limits === 'object') ? t.feature_limits : { databases: 5, backups: 5, allocations: 5 } }; }).filter(function(t){ return t.id; });
    const r = await dbRead('panel-templates.json', true); await dbWrite('panel-templates.json', clean, r.sha || null, 'admin: panel-templates'); try { await dbRead('panel-templates.json', true); } catch(e) {}
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});

router.get('/api/admin/vouchers', adminAuth, async function(req, res) { try { const r = await dbRead('vouchers.json'); res.json({ ok: true, data: Array.isArray(r.data) ? r.data : [], sha: r.sha }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.post('/api/admin/vouchers', adminAuth, async function(req, res) {
  try {
    const vouchers = Array.isArray(req.body) ? req.body : (req.body.vouchers || []);
    const clean = vouchers.map(function(v) { return { id: String(v.id || ('vc-' + Date.now())), code: String(v.code || '').toUpperCase().trim().replace(/[^A-Z0-9_-]/g,'').slice(0,20), type: ['percent','nominal'].includes(v.type) ? v.type : 'percent', value: Math.max(0, parseInt(v.value, 10) || 0), minOrder: Math.max(0, parseInt(v.minOrder, 10) || 0), maxDiscount: Math.max(0, parseInt(v.maxDiscount, 10) || 0), usedCount: parseInt(v.usedCount, 10) || 0, maxUse: parseInt(v.maxUse, 10) || 0, expiresAt: v.expiresAt ? parseInt(v.expiresAt, 10) : null, active: v.active !== false, productIds: Array.isArray(v.productIds) ? v.productIds : [], desc: String(v.desc || '').slice(0, 100) }; }).filter(function(v){ return v.code; });
    const r = await dbRead('vouchers.json', true); await dbWrite('vouchers.json', clean, r.sha || null, 'admin: vouchers'); res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});

var _analyticsCache = null, _analyticsCacheAt = 0;
const ANALYTICS_TTL = 5 * 60 * 1000;
router.get('/api/admin/analytics', adminAuth, async function(req, res) {
  const forceRefresh = req.query.refresh === '1';
  if (!forceRefresh && _analyticsCache && (Date.now() - _analyticsCacheAt) < ANALYTICS_TTL) return res.json(Object.assign({ ok: true, cached: true }, _analyticsCache));
  try {
    const now = Date.now(); const D7 = now - 7 * 86400000; const D30 = now - 30 * 86400000;
    const dailyMap = {}; for (let i = 0; i < 30; i++) { const d = new Date(now - i * 86400000); const key = d.toISOString().slice(0, 10); dailyMap[key] = { date: key, revenue: 0, orders: 0, completed: 0 }; }
    const monthMap = {}; for (let i = 0; i < 12; i++) { const d = new Date(now); d.setDate(1); d.setMonth(d.getMonth() - i); const key = d.toISOString().slice(0, 7); monthMap[key] = { month: key, revenue: 0, orders: 0, depositFee: 0, sewabot: 0 }; }
    const productCount = {}; let revProduct = 0, revDepFee = 0, revSewabot = 0, rev7 = 0, ord30 = 0, totalOrd = 0, completedTotal = 0, failedTotal = 0, pendingTotal = 0, convNumer = 0, convDenom = 0;
    const files = await listTrx(); const trxFiles = files.filter(function(f){ return f.name.endsWith('.json'); });
    const BATCH = 12; const trxList = [];
    for (let bi = 0; bi < trxFiles.length; bi += BATCH) {
      const batch = await Promise.all(trxFiles.slice(bi, bi + BATCH).map(async function(f) { try { const r = await dbRead('transactions/' + f.name); return r.data || null; } catch(e) { return null; } }));
      batch.forEach(function(d) { if (d) trxList.push(d); });
      if (bi + BATCH < trxFiles.length) await _sleep(80);
    }
    trxList.forEach(function(t) {
      const ts = t.createdAt || 0; const dayKey = new Date(ts).toISOString().slice(0, 10); const monKey = new Date(ts).toISOString().slice(0, 7);
      totalOrd++; convDenom++;
      if (t.status === 'COMPLETED') {
        completedTotal++; convNumer++; const rv = t.totalBayar || t.unitPrice || 0;
        if (t.type === 'sewabot' || t.productType === 'sewabot') { revSewabot += rv; if (monthMap[monKey]) monthMap[monKey].sewabot += rv; }
        else { revProduct += rv; if (monthMap[monKey]) monthMap[monKey].revenue += rv; }
        if (ts > D30) ord30++; if (ts > D7) rev7 += rv;
        if (dailyMap[dayKey]) { dailyMap[dayKey].revenue += rv; dailyMap[dayKey].completed++; }
        const pid = t.productName || t.productId || 'Unknown'; productCount[pid] = (productCount[pid] || 0) + 1;
      } else if (['FAILED','CANCELLED','EXPIRED'].includes(t.status)) { failedTotal++; } else { pendingTotal++; }
      if (dailyMap[dayKey]) dailyMap[dayKey].orders++;
      if (monthMap[monKey]) monthMap[monKey].orders++;
    });
    try {
      const depListR = await listDirCached('deposits'); const depFiles = Array.isArray(depListR) ? depListR.filter(function(f){ return f.name.endsWith('.json'); }) : [];
      for (let bi = 0; bi < depFiles.length; bi += BATCH) {
        const batch = await Promise.all(depFiles.slice(bi, bi + BATCH).map(async function(f) { try { const dr = await getDeposit(f.name.replace('.json','')); return dr.data || null; } catch(e) { return null; } }));
        batch.forEach(function(d) { if (!d || d.status !== 'success') return; const fee = d.adminFeeDeposit || 0; const ts = d.createdAt || 0; revDepFee += fee; const dayKey = new Date(ts).toISOString().slice(0, 10); const monKey = new Date(ts).toISOString().slice(0, 7); if (dailyMap[dayKey]) dailyMap[dayKey].revenue += fee; if (monthMap[monKey]) monthMap[monKey].depositFee += fee; });
        if (bi + BATCH < depFiles.length) await _sleep(80);
      }
    } catch(e) {}
    const totalRev = revProduct + revDepFee + revSewabot;
    const daily    = Object.values(dailyMap).sort(function(a, b){ return a.date.localeCompare(b.date); });
    const monthly  = Object.values(monthMap).sort(function(a, b){ return b.month.localeCompare(a.month); });
    const topProducts = Object.entries(productCount).sort(function(a, b){ return b[1] - a[1]; }).slice(0, 10).map(function(e){ return { name: e[0], count: e[1] }; });
    const result = { summary: { totalRev, totalOrd, rev7, ord30, revProduct, revDepFee, revSewabot, completedTotal, failedTotal, pendingTotal, conversionRate: convDenom > 0 ? Math.round(convNumer / convDenom * 100) : 0, avgOrderValue: completedTotal > 0 ? Math.round(revProduct / completedTotal) : 0 }, daily, monthly, topProducts };
    _analyticsCache = result; _analyticsCacheAt = Date.now();
    res.json(Object.assign({ ok: true }, result));
  } catch(e) { res.json({ ok: false, message: e.message }); }
});

router.get('/api/admin/deposits', adminAuth, async function(req, res) {
  try {
    let deps = []; try { const r = await listDirCached('deposits'); const files = Array.isArray(r) ? r.filter(function(f){ return f.name.endsWith('.json'); }) : []; await Promise.all(files.map(async function(f) { try { const d = await getDeposit(f.name.replace('.json','')); if (d.data) deps.push({ id: d.data.id, username: d.data.username, amount: d.data.amount, adminFeeDeposit: d.data.adminFeeDeposit || 0, totalBayarDeposit: d.data.totalBayarDeposit || d.data.amount, status: d.data.status, createdAt: d.data.createdAt, expiredAt: d.data.expiredAt || null, paidAt: d.data.paidAt || null }); } catch(e) {} })); } catch(e) {}
    deps.sort(function(a,b){ return (b.createdAt||0)-(a.createdAt||0); }); res.json({ ok: true, data: deps.slice(0, 200) });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.post('/api/admin/deposits/reconcile', adminAuth, async function(req, res) { reconcileAllPendingDeposits().catch(function(){}); res.json({ ok: true, message: 'Reconcile deposit dijadwalkan.' }); });
router.get('/api/admin/event-trigger/status', adminAuth, function(req, res) { res.json({ ok: true, watchers: eventTrigger._status() }); });

// ─── Backup (ZIP) ─────────────────────────────────────────────────────────────
//
// Semua mode menghasilkan file .zip langsung (tidak ada base64 / JSON wrapper).
// Gunakan query string:  GET /api/admin/backup?mode=1 | 2 | 3
//
//   Mode 1 – Source code website only
//             source/  ← seluruh file .js/.html/.json/.css/dst dari disk
//             (node_modules, data/, media/ dikecualikan)
//
//   Mode 2 – Semua database + CDN files + source code
//             source/  ← source code
//             database/  ← semua file JSON database (flat maupun koleksi)
//             cdn/  ← semua file CDN sebagai file asli (binary/text apa adanya)
//
//   Mode 3 – Semua database + source code  (tanpa CDN)
//             source/  ← source code
//             database/  ← semua file JSON database
//
// Default (tanpa ?mode) = mode 3, untuk backward compat.
// ─────────────────────────────────────────────────────────────────────────────

var archiver = require('archiver');
var fsSync   = require('fs');
var pathMod  = require('path');
var multer   = require('multer');
var AdmZip   = require('adm-zip');

// Multer: terima ZIP di memori, max 500 MB
var _backupUpload = multer({
  storage: multer.memoryStorage(),
  limits : { fileSize: 500 * 1024 * 1024 },
  fileFilter: function(req, file, cb) {
    cb(null, file.mimetype === 'application/zip' || file.originalname.endsWith('.zip'));
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// BACKUP
//
//   GET /api/admin/backup?mode=1 | 2 | 3
//
//   Mode 1 – Source code only
//             ZIP = struktur folder asli web (index.js, lib/, routes/, public/, dst.)
//             node_modules/, data/, media/ dikecualikan.
//
//   Mode 2 – Source code + database + CDN
//             ZIP berisi:
//               • struktur asli source code (sama seperti mode 1)
//               • data/          ← semua file JSON database (flat & koleksi)
//               • data/cdn/      ← semua file CDN sebagai file asli
//
//   Mode 3 – Source code + database  (tanpa CDN)  [default]
//             ZIP berisi:
//               • struktur asli source code
//               • data/          ← semua file JSON database
//
// Struktur ZIP = struktur asli sehingga tinggal ekstrak → langsung bisa run.
// ─────────────────────────────────────────────────────────────────────────────

/* ── helper: source code → archive dengan struktur asli ─────────────────────── */
function _archiveSourceCode(archive) {
  var ROOT        = pathMod.resolve(__dirname, '..');
  var SRC_EXT     = new Set(['.js','.mjs','.cjs','.json','.html','.htm','.css','.md','.txt','.yml','.yaml','.env','.example','.sh','.bat','.ps1']);
  var IGNORE_DIRS = new Set(['node_modules','.git','data','media','.nyc_output','coverage','dist','build','tmp']);

  function walk(dir, rel) {
    var entries;
    try { entries = fsSync.readdirSync(dir, { withFileTypes: true }); } catch(e) { return; }
    for (var i = 0; i < entries.length; i++) {
      var entry   = entries[i];
      var relPath = rel ? rel + '/' + entry.name : entry.name;
      if (entry.isDirectory()) {
        if (!IGNORE_DIRS.has(entry.name)) walk(pathMod.join(dir, entry.name), relPath);
      } else if (entry.isFile()) {
        var ext = pathMod.extname(entry.name).toLowerCase();
        if (SRC_EXT.has(ext) || SRC_EXT.has(entry.name)) {
          try {
            var fullPath = pathMod.join(dir, entry.name);
            if (fsSync.statSync(fullPath).size < 5 * 1024 * 1024) {
              // nama di ZIP = path relatif asli, tanpa prefix apapun
              archive.file(fullPath, { name: relPath });
            }
          } catch(e) {}
        }
      }
    }
  }
  walk(ROOT, '');
}

/* ── helper: file DB → archive di bawah data/ (struktur asli) ──────────────── */
async function _archiveDbFiles(archive) {
  var TOP_LEVEL_FILES = [
    'settings.json','products.json','categories.json','slides.json',
    'accounts.json','panel-templates.json','vouchers.json','ad-config.json',
    'otp-pinned.json','feed-cache.json','audit.json',
  ];
  for (var i = 0; i < TOP_LEVEL_FILES.length; i++) {
    try {
      var r = await dbRead(TOP_LEVEL_FILES[i]);
      if (r.data !== null && r.data !== undefined)
        archive.append(JSON.stringify(r.data, null, 2), { name: 'data/' + TOP_LEVEL_FILES[i] });
    } catch(e) {}
  }
  var COLLECTION_DIRS = ['transactions','deposits','otp-orders','users','reseller-servers'];
  for (var d = 0; d < COLLECTION_DIRS.length; d++) {
    var dir = COLLECTION_DIRS[d];
    try {
      var files = await listDirCached(dir);
      var arr   = Array.isArray(files) ? files.filter(function(f){ return f.name.endsWith('.json'); }) : [];
      for (var f = 0; f < arr.length; f++) {
        try {
          var fr = await dbRead(dir + '/' + arr[f].name);
          if (fr.data) archive.append(JSON.stringify(fr.data, null, 2), { name: 'data/' + dir + '/' + arr[f].name });
        } catch(e) {}
        if (f % 20 === 0 && f > 0) await _sleep(100);
      }
    } catch(e) {}
  }
}

/* ── helper: file CDN → archive di bawah data/cdn/ (struktur asli) ─────────── */
async function _archiveCdnFiles(archive) {
  var { cdnListFiles, cdnReadFile, cdnGetDirectUrl } = require('../lib/cdn');
  var list = await cdnListFiles();
  for (var i = 0; i < list.length; i++) {
    var f = list[i];
    try {
      // Mode local: baca dari disk
      var buf = cdnReadFile ? await cdnReadFile(f.name) : null;

      // Mode external: cdnReadFile returns null → fetch langsung dari dongtube URL
      if (!buf && typeof cdnGetDirectUrl === 'function') {
        var directUrl = await cdnGetDirectUrl(f.name);
        if (!directUrl && f.url && /^https?:\/\//.test(f.url)) directUrl = f.url;
        if (directUrl) {
          var ac  = new AbortController();
          var tid = setTimeout(function() { ac.abort(); }, 30000);
          try {
            var resp = await fetch(directUrl, { signal: ac.signal });
            clearTimeout(tid);
            if (resp.ok) buf = Buffer.from(await resp.arrayBuffer());
          } catch(_e) { clearTimeout(tid); }
        }
      }

      if (buf) archive.append(buf, { name: 'data/cdn/' + f.name });
    } catch(e) {}
    if (i % 10 === 0 && i > 0) await _sleep(50);
  }
}

/* ── BACKUP route ────────────────────────────────────────────────────────────── */
router.get('/api/admin/backup', adminAuth, async function(req, res) {
  var mode = parseInt(req.query.mode, 10) || 3;
  if (mode < 1 || mode > 3) return res.status(400).json({ ok: false, message: 'mode harus 1, 2, atau 3.' });

  var timestamp = moment().tz('Asia/Jakarta').format('YYYY-MM-DD_HH-mm-ss');
  var modeLabel = ['source-only', 'full', 'db-source'][mode - 1];
  var filename  = 'dongtube-backup-mode' + mode + '-' + modeLabel + '-' + timestamp + '.zip';

  res.setHeader('Content-Type',        'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
  res.setHeader('Cache-Control',       'no-store');

  var archive = archiver('zip', { zlib: { level: 6 } });
  archive.on('error', function(err) {
    console.error('[backup] archiver error:', err.message);
    res.end();
  });
  archive.pipe(res);

  try {
    // manifest.json → tetap ada di root ZIP sebagai penanda
    archive.append(JSON.stringify({
      version      : '3.0.0',
      backupMode   : mode,
      modeLabel    : modeLabel,
      exportedAt   : Date.now(),
      exportedAtStr: new Date().toISOString(),
      note         : 'Ekstrak ZIP ini langsung ke folder project — struktur folder sudah sama dengan aslinya.',
    }, null, 2), { name: 'manifest.json' });

    if (mode === 1) {
      _archiveSourceCode(archive);
    } else if (mode === 2) {
      _archiveSourceCode(archive);
      await _archiveDbFiles(archive);
      await _archiveCdnFiles(archive);
    } else {
      _archiveSourceCode(archive);
      await _archiveDbFiles(archive);
    }

    await archive.finalize();
    auditLog('backup', 'Mode ' + mode + ' (' + modeLabel + ') ZIP', req.adminIp).catch(function(){});
    console.log('[backup] mode=' + mode + ' selesai dari', req.adminIp);
  } catch(e) {
    console.error('[backup]', e.message);
    try { archive.abort(); } catch(_) {}
    res.end();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// IMPORT  —  POST /api/admin/import
//
// Terima file ZIP hasil backup (semua mode), lalu restore isinya:
//   • File di data/*.json         → dbWrite ke database (local/external otomatis)
//   • File di data/<dir>/*.json   → dbWrite ke koleksi
//   • File di data/cdn/*          → cdnUploadFile ke CDN (local/external otomatis)
//   • Source code (*.js, dll)     → DIABAIKAN (tidak ditimpa saat import)
//
// Query opsional:
//   ?skip_cdn=1     → abaikan file CDN meski ada di ZIP
//   ?overwrite=1    → (default) timpa data yang sudah ada
//
// Response: { ok, imported: { db: N, cdn: N }, skipped: N, errors: [...] }
// ─────────────────────────────────────────────────────────────────────────────

var DB_TOP_LEVEL = new Set([
  'settings.json','products.json','categories.json','slides.json',
  'accounts.json','panel-templates.json','vouchers.json','ad-config.json',
  'otp-pinned.json','feed-cache.json','audit.json',
]);
var DB_COLLECTIONS = new Set(['transactions','deposits','otp-orders','users','reseller-servers']);

router.post('/api/admin/import', adminAuth, function(req, res) {
  _backupUpload.single('backup')(req, res, async function(err) {
    if (err) return res.status(400).json({ ok: false, message: 'Upload gagal: ' + err.message });
    if (!req.file || !req.file.buffer) return res.status(400).json({ ok: false, message: 'File backup tidak ditemukan. Kirim sebagai multipart field "backup".' });

    var skipCdn = req.query.skip_cdn === '1' || req.query.skip_cdn === 'true';

    var stats  = { db: 0, cdn: 0 };
    var skipped = 0;
    var errors  = [];

    try {
      var zip     = new AdmZip(req.file.buffer);
      var entries = zip.getEntries();

      // ── Pisahkan entry berdasarkan tipe ───────────────────────────────────
      var dbEntries  = []; // data/*.json atau data/<koleksi>/*.json
      var cdnEntries = []; // data/cdn/*

      for (var i = 0; i < entries.length; i++) {
        var entry = entries[i];
        if (entry.isDirectory) continue;

        var name = entry.entryName.replace(/\\/g, '/'); // normalize Windows path

        if (name === 'manifest.json') { skipped++; continue; } // lewati manifest

        if (name.startsWith('data/cdn/')) {
          if (!skipCdn) cdnEntries.push(entry);
          else skipped++;
        } else if (name.startsWith('data/')) {
          dbEntries.push(entry);
        } else {
          skipped++; // source code dll — tidak di-import
        }
      }

      // ── Restore DB files ──────────────────────────────────────────────────
      for (var di = 0; di < dbEntries.length; di++) {
        var dbEntry  = dbEntries[di];
        var dbName   = dbEntry.entryName.replace(/\\/g, '/').replace(/^data\//, '');
        // dbName contoh: "settings.json" | "transactions/TRX-xxx.json"

        if (!dbName.endsWith('.json')) { skipped++; continue; }

        var parts = dbName.split('/');

        // Validasi: harus top-level yang dikenal ATAU koleksi yang dikenal
        var isTopLevel   = parts.length === 1 && DB_TOP_LEVEL.has(parts[0]);
        var isCollection = parts.length === 2 && DB_COLLECTIONS.has(parts[0]);
        if (!isTopLevel && !isCollection) { skipped++; continue; }

        try {
          var rawJson = dbEntry.getData().toString('utf8');
          var parsed  = JSON.parse(rawJson);
          // Baca SHA terkini dulu (penting untuk external DB agar tidak konflik)
          var existing = await dbRead(dbName);
          await dbWrite(dbName, parsed, existing.sha || null, 'import: ' + dbName);
          stats.db++;
        } catch(e) {
          errors.push({ file: 'data/' + dbName, error: e.message });
        }

        if (di % 20 === 0 && di > 0) await _sleep(80);
      }

      // ── Restore CDN files ─────────────────────────────────────────────────
      if (!skipCdn && cdnEntries.length > 0) {
        var { cdnUploadFile } = require('../lib/cdn');
        for (var ci = 0; ci < cdnEntries.length; ci++) {
          var cdnEntry    = cdnEntries[ci];
          var cdnFilename = pathMod.basename(cdnEntry.entryName.replace(/\\/g, '/'));
          if (!cdnFilename) { skipped++; continue; }
          try {
            var cdnBuf = cdnEntry.getData();
            await cdnUploadFile(cdnFilename, cdnBuf);
            stats.cdn++;
          } catch(e) {
            errors.push({ file: 'data/cdn/' + cdnFilename, error: e.message });
          }
          if (ci % 5 === 0 && ci > 0) await _sleep(100);
        }
      }

      // Invalidasi cache setelah import massal
      if (typeof _dbCacheInvalidate === 'function') {
        try { _dbCacheInvalidate(); } catch(_) {}
      }
      if (typeof _cdnInvalidateCache === 'function') {
        try { _cdnInvalidateCache(); } catch(_) {}
      }

      auditLog('import', 'DB:' + stats.db + ' CDN:' + stats.cdn + ' skip:' + skipped + ' err:' + errors.length, req.adminIp).catch(function(){});
      console.log('[import] selesai — DB:', stats.db, 'CDN:', stats.cdn, 'skip:', skipped, 'error:', errors.length);

      res.json({
        ok      : true,
        message : 'Import selesai.',
        imported: stats,
        skipped : skipped,
        errors  : errors.slice(0, 50), // max 50 error ditampilkan
      });

    } catch(e) {
      console.error('[import] fatal:', e.message);
      res.status(500).json({ ok: false, message: 'Import gagal: ' + e.message });
    }
  });
});

router.get('/api/ad', async function(req, res) { try { const r = await dbRead('ad-config.json'); const d = r.data || {}; res.json({ ok: true, enabled: d.enabled === true, imageUrl: d.imageUrl || '', text: d.text || '', linkUrl: d.linkUrl || '' }); } catch(e) { res.json({ ok: false, enabled: false }); } });
router.get('/api/admin/ad', adminAuth, async function(req, res) { try { const r = await dbRead('ad-config.json'); res.json({ ok: true, data: r.data || { enabled: false, imageUrl: '', text: '', linkUrl: '' } }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.post('/api/admin/ad', adminAuth, async function(req, res) {
  try {
    var enabled = req.body.enabled === true || req.body.enabled === 'true'; var imageUrl = String(req.body.imageUrl || '').trim().slice(0, 500); var text = String(req.body.text || '').trim().slice(0, 300); var linkUrl = String(req.body.linkUrl || '').trim().slice(0, 500);
    if (imageUrl && !imageUrl.startsWith('http')) return res.json({ ok: false, message: 'URL gambar harus dimulai dengan http/https.' });
    if (linkUrl  && !linkUrl.startsWith('http'))  return res.json({ ok: false, message: 'URL link harus dimulai dengan http/https.' });
    const r = await dbRead('ad-config.json', true); await dbWrite('ad-config.json', { enabled, imageUrl, text, linkUrl }, r.sha || null, 'admin: ad-config');
    auditLog('ad-update', (enabled ? 'enabled' : 'disabled'), req.adminIp).catch(function(e) {}); res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});

router.get('/api/admin/ulasan', adminAuth, async function(req, res) { try { var r = await getReviews(); var arr = Array.isArray(r.data) ? r.data : []; arr = arr.slice().sort(function(a,b){ return (b.createdAt||0) - (a.createdAt||0); }); res.json({ ok: true, data: arr }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.post('/api/admin/ulasan/:id/approve', adminAuth, async function(req, res) {
  try {
    var id = req.params.id; if (!id || !/^REV-\d{13}-[a-f0-9]{8}$/.test(id)) return res.json({ ok: false, message: 'ID tidak valid.' });
    var approved = req.body.approved !== false;
    for (var _rt = 0; _rt < 3; _rt++) { try { var fr = await getReviews(); var arr = Array.isArray(fr.data) ? fr.data : []; var idx = arr.findIndex(function(rv) { return rv.id === id; }); if (idx < 0) return res.json({ ok: false, message: 'Ulasan tidak ditemukan.' }); arr[idx] = Object.assign({}, arr[idx], { approved, approvedAt: Date.now() }); await saveReviews(arr, fr.sha || null); break; } catch(e) { if (_rt < 2 && (e.status === 409 || e.status === 422)) { await _sleep(300*(_rt+1)); continue; } throw e; } }
    auditLog(approved ? 'approve-review' : 'unapprove-review', id, req.adminIp).catch(function(e) {}); res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.delete('/api/admin/ulasan/reset-all', adminAuth, async function(req, res) { try { var fr = await getReviews(); await saveReviews([], fr.sha || null); auditLog('clear-reviews', 'Semua ulasan dihapus via reset-all', req.adminIp).catch(function(){}); res.json({ ok: true, message: 'Semua ulasan dihapus.' }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.post('/api/admin/ulasan/bulk-delete', adminAuth, async function(req, res) {
  try {
    var ids = req.body.ids; if (!Array.isArray(ids) || ids.length === 0) return res.json({ ok: false, message: 'Tidak ada ID yang dikirim.' });
    var idSet = new Set(ids.filter(function(id){ return typeof id === 'string' && /^REV-\d{13}-[a-f0-9]{8}$/.test(id); })); if (!idSet.size) return res.json({ ok: false, message: 'ID tidak valid.' });
    for (var _rt = 0; _rt < 3; _rt++) { try { var fr = await getReviews(); var arr = (Array.isArray(fr.data) ? fr.data : []).filter(function(rv){ return !idSet.has(rv.id); }); await saveReviews(arr, fr.sha || null); break; } catch(e) { if (_rt < 2 && (e.status === 409 || e.status === 422)) { await _sleep(300*(_rt+1)); continue; } throw e; } }
    auditLog('bulk-delete-reviews', idSet.size + ' ulasan dihapus', req.adminIp).catch(function(){}); res.json({ ok: true, deleted: idSet.size });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});
router.delete('/api/admin/ulasan/:id', adminAuth, async function(req, res) {
  try { var id = req.params.id; if (!id || !/^REV-\d{13}-[a-f0-9]{8}$/.test(id)) return res.json({ ok: false, message: 'ID tidak valid.' }); for (var _rt = 0; _rt < 3; _rt++) { try { var fr = await getReviews(); var arr = Array.isArray(fr.data) ? fr.data : []; var idx = arr.findIndex(function(rv) { return rv.id === id; }); if (idx < 0) return res.json({ ok: false, message: 'Ulasan tidak ditemukan.' }); arr.splice(idx, 1); await saveReviews(arr, fr.sha || null); break; } catch(e) { if (_rt < 2 && (e.status === 409 || e.status === 422)) { await _sleep(300*(_rt+1)); continue; } throw e; } } auditLog('delete-review', id, req.adminIp).catch(function(){}); res.json({ ok: true }); }
  catch(e) { res.json({ ok: false, message: e.message }); }
});
router.get('/api/admin/chat', adminAuth, async function(req, res) { try { var r = await getChatMessages(); var arr = Array.isArray(r.data) ? r.data : []; arr = arr.slice().sort(function(a,b){ return (b.createdAt||0) - (a.createdAt||0); }); res.json({ ok: true, data: arr }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.delete('/api/admin/chat/reset-all', adminAuth, async function(req, res) { try { var fr = await getChatMessages(); await saveChatMessages([], fr.sha || null); auditLog('clear-chat', 'Semua chat dihapus via reset-all', req.adminIp).catch(function(){}); res.json({ ok: true, message: 'Semua pesan chat dihapus.' }); } catch(e) { res.json({ ok: false, message: e.message }); } });
router.post('/api/admin/chat/bulk-delete', adminAuth, async function(req, res) {
  try { var ids = req.body.ids; if (!Array.isArray(ids) || ids.length === 0) return res.json({ ok: false, message: 'Tidak ada ID yang dikirim.' }); var idSet = new Set(ids.filter(function(id){ return typeof id === 'string' && /^MSG-\d{13}-[a-f0-9]{8}$/.test(id); })); if (!idSet.size) return res.json({ ok: false, message: 'ID tidak valid.' }); for (var _rt = 0; _rt < 3; _rt++) { try { var fr = await getChatMessages(); var arr = (Array.isArray(fr.data) ? fr.data : []).filter(function(m){ return !idSet.has(m.id); }); await saveChatMessages(arr, fr.sha || null); break; } catch(e) { if (_rt < 2 && (e.status === 409 || e.status === 422)) { await _sleep(200*(_rt+1)); continue; } throw e; } } auditLog('bulk-delete-chat', idSet.size + ' pesan dihapus', req.adminIp).catch(function(){}); res.json({ ok: true, deleted: idSet.size }); }
  catch(e) { res.json({ ok: false, message: e.message }); }
});
router.delete('/api/admin/chat/:id', adminAuth, async function(req, res) {
  try { var id = req.params.id; if (!id || !/^MSG-\d{13}-[a-f0-9]{8}$/.test(id)) return res.json({ ok: false, message: 'ID tidak valid.' }); for (var _rt = 0; _rt < 3; _rt++) { try { var fr = await getChatMessages(); var arr = Array.isArray(fr.data) ? fr.data : []; var idx = arr.findIndex(function(m) { return m.id === id; }); if (idx < 0) return res.json({ ok: false, message: 'Pesan tidak ditemukan.' }); arr.splice(idx, 1); await saveChatMessages(arr, fr.sha || null); break; } catch(e) { if (_rt < 2 && (e.status === 409 || e.status === 422)) { await _sleep(200*(_rt+1)); continue; } throw e; } } res.json({ ok: true }); }
  catch(e) { res.json({ ok: false, message: e.message }); }
});
router.delete('/api/admin/chat', adminAuth, async function(req, res) { try { var fr = await getChatMessages(); await saveChatMessages([], fr.sha || null); auditLog('clear-chat', 'Chat dihapus', req.adminIp).catch(function(){}); res.json({ ok: true, message: 'Semua pesan chat dihapus.' }); } catch(e) { res.json({ ok: false, message: e.message }); } });



module.exports = router;
