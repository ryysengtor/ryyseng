'use strict';

const express = require('express');
const axios   = require('axios');
const crypto  = require('crypto');
const router  = express.Router();

const C        = require('../lib/config');
const { rateLimit, adminAuth } = require('../lib/auth');
const { makeToken, verifyToken } = require('../lib/auth');
const { listDirCached, _gitTreeCache, dbRead, dbWrite, dbDelete } = require('../lib/db');
const { getRsServer, saveRsServer, getPanelTemplates, hashPassword, verifyPassword, auditLog, _sleep } = require('../lib/models');
const { ptH, SPEC, sanitizeUsername, createPanelServer, deleteServer, suspendServer, unsuspendServer, getServerDetails, updateExpiryDescription, extendServerExpiry } = require('../lib/panel');

const SESSION_TTL = 30 * 24 * 60 * 60 * 1000;
const RESELLER_RE = /^[a-z0-9_]{3,20}$/;
function isValidResellerUsername(u) { return RESELLER_RE.test(u); }

async function getReseller(username)          { return dbRead('resellers/' + username + '.json'); }
async function saveReseller(username, d, sha) { return dbWrite('resellers/' + username + '.json', d, sha, 'reseller:' + username); }
async function listResellers() { try { return await listDirCached('resellers'); } catch(e) { return []; } }
async function listRsServersOf(resellerUsername) {
  try {
    var files = (await listDirCached('reseller-servers')).filter(function(f){ return f.name.endsWith('.json'); });
    var results = [];
    await Promise.all(files.map(async function(f) { try { var r = await getRsServer(f.name.replace('.json','')); if (r.data && r.data.resellerUsername === resellerUsername) results.push(r.data); } catch(e) {} }));
    return results.sort(function(a,b){ return (b.createdAt||0)-(a.createdAt||0); });
  } catch(e) { return []; }
}

function makeResellerToken(username) { return makeToken({ sub: username, role: 'reseller', iat: Date.now(), exp: Date.now() + SESSION_TTL }); }
function resellerAuth(req, res, next) {
  var token   = req.headers['x-reseller-token'];
  var payload = verifyToken(token);
  if (!payload || payload.role !== 'reseller' || !payload.sub) return res.status(401).json({ ok: false, message: 'Login diperlukan.' });
  req.resellerUser = payload.sub; next();
}

router.post('/api/reseller/login', async function(req, res) {
  var ip = req.ip || 'x';
  if (!rateLimit('rslogin:' + ip, 5, 15 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak percobaan.' });
  var username = String(req.body.username || '').toLowerCase().trim(); var password = String(req.body.password || '');
  if (!isValidResellerUsername(username) || !password) return res.json({ ok: false, message: 'Username atau password tidak valid.' });
  try {
    var r = await getReseller(username);
    if (!r.data || r.data.deleted) return res.json({ ok: false, message: 'Username atau password salah.' });
    if (r.data.active === false) return res.json({ ok: false, message: 'Akun dinonaktifkan. Hubungi admin.' });
    var valid = await verifyPassword(password, r.data.passwordHash);
    if (!valid) { console.warn('[reseller] login gagal:', username, ip); return res.json({ ok: false, message: 'Username atau password salah.' }); }
    await saveReseller(username, Object.assign({}, r.data, { lastLogin: Date.now() }), r.sha);
    res.json({ ok: true, token: makeResellerToken(username) });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/reseller/profile', resellerAuth, async function(req, res) {
  try {
    var r = await getReseller(req.resellerUser);
    if (!r.data || r.data.deleted) return res.json({ ok: false, message: 'Akun tidak ditemukan.' });
    if (r.data.active === false) return res.status(403).json({ ok: false, message: 'Akun dinonaktifkan.' });
    var servers = await listRsServersOf(req.resellerUser);
    var activeCount = servers.filter(function(s){ return s.status !== 'deleted'; }).length;
    res.json({ ok: true, data: { username: r.data.username, allowedPlans: r.data.allowedPlans || [], maxServers: r.data.maxServers || 10, activeServers: activeCount, createdAt: r.data.createdAt } });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/reseller/change-password', resellerAuth, async function(req, res) {
  if (!rateLimit('rs-chgpwd:' + req.resellerUser, 5, 15 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.' });
  try {
    var oldPwd = String(req.body.oldPassword || '');
    var newPwd = String(req.body.newPassword || '').trim();
    if (!newPwd || newPwd.length < 6) return res.json({ ok: false, message: 'Password baru minimal 6 karakter.' });
    if (newPwd.length > 72) return res.json({ ok: false, message: 'Password terlalu panjang.' });
    var r = await getReseller(req.resellerUser);
    if (!r.data || r.data.deleted) return res.json({ ok: false, message: 'Akun tidak ditemukan.' });
    var valid = await verifyPassword(oldPwd, r.data.passwordHash);
    if (!valid) return res.json({ ok: false, message: 'Password lama tidak cocok.' });
    var hashed = await hashPassword(newPwd);
    await saveReseller(req.resellerUser, Object.assign({}, r.data, { passwordHash: hashed, pwChangedAt: Date.now() }), r.sha);
    auditLog('change-reseller-pwd', req.resellerUser, req.ip).catch(function(){});
    res.json({ ok: true, message: 'Password berhasil diubah.' });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/reseller/plans', resellerAuth, async function(req, res) {
  try {
    var r = await getReseller(req.resellerUser);
    if (!r.data || r.data.deleted || r.data.active === false) return res.status(403).json({ ok: false, message: 'Akun tidak valid.' });
    var allowedPlans = r.data.allowedPlans || []; var templates = await getPanelTemplates();
    var all = Object.keys(SPEC).map(function(id) { var t = templates.find(function(x){ return x.id === id; }); return t || { id, name: id.toUpperCase(), ram: SPEC[id].ram, disk: SPEC[id].disk, cpu: SPEC[id].cpu, active: true }; });
    templates.forEach(function(t) { if (!SPEC[t.id]) all.push(t); });
    var plans = (allowedPlans.length > 0) ? all.filter(function(p){ return allowedPlans.includes(p.id) && p.active !== false; }) : all.filter(function(p){ return p.active !== false; });
    res.json({ ok: true, data: plans, domain: C.ptero.domain });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/reseller/create-panel', resellerAuth, async function(req, res) {
  var ip = req.ip || 'x';
  if (!rateLimit('rscreate:' + req.resellerUser, 3, 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
  try {
    var rawUsername   = String(req.body.username || '').trim();
    var panelUsername = sanitizeUsername(rawUsername);
    var panelPassword = String(req.body.password || '').trim();
    var plan          = String(req.body.plan || '').toLowerCase().replace(/[^a-z0-9_]/g,'').slice(0,20);
    var days          = Math.max(1, Math.min(3650, parseInt(req.body.days, 10) || 30));

    if (!panelUsername || panelUsername.length < 3) return res.json({ ok: false, message: 'Username panel minimal 3 karakter (hanya huruf kecil, angka, underscore). Kamu memasukkan: "' + rawUsername + '"' });
    if (!panelPassword || panelPassword.length < 6)  return res.json({ ok: false, message: 'Password panel minimal 6 karakter.' });
    if (!plan) return res.json({ ok: false, message: 'Pilih plan terlebih dahulu.' });
    if (!C.ptero.domain || !C.ptero.apikey) return res.json({ ok: false, message: 'Server Pterodactyl belum dikonfigurasi. Hubungi admin.' });

    var rr = await getReseller(req.resellerUser);
    if (!rr.data || rr.data.deleted || rr.data.active === false) return res.status(403).json({ ok: false, message: 'Akun reseller tidak valid.' });

    var allowedPlans = rr.data.allowedPlans || [];
    if (allowedPlans.length > 0 && !allowedPlans.includes(plan)) return res.json({ ok: false, message: 'Plan tidak diizinkan untuk akun ini.' });

    var maxServers = rr.data.maxServers || 10;
    var servers = await listRsServersOf(req.resellerUser);
    var activeCount = servers.filter(function(s){ return s.status !== 'deleted'; }).length;
    if (activeCount >= maxServers) return res.json({ ok: false, message: 'Anda sudah mencapai limit server (' + maxServers + ').' });

    var created = await createPanelServer(plan, days, 'RS-' + req.resellerUser, panelUsername, panelPassword);

    const now = Date.now();
    const rsServerId = crypto.randomBytes(8).toString('hex');
    const serverData = {
      id: rsServerId,
      resellerUsername: req.resellerUser,
      serverId: created.serverId,
      userId: created.userId,
      username: created.username,
      panelUsername: created.username,
      plan: plan,
      ram: created.ram,
      disk: created.disk,
      cpu: created.cpu,
      days: days,
      createdAt: now,
      createdFromIp: ip,
      expiresAt: created.expiresAt,
      purchaseDate: created.purchaseDate,
      domain: created.domain,
      status: 'active',
    };

    await saveRsServer(rsServerId, serverData, null);
    _gitTreeCache.delete('reseller-servers');
    auditLog('create-rs-server', rsServerId + ' (' + panelUsername + ')', req.ip).catch(function(){});

    // ── Event-driven: jadwalkan auto-suspend saat server expired ─────────────
    if (serverData.expiresAt && serverData.serverId) {
      require('../lib/event-trigger').triggerRsServerExpiry(rsServerId, serverData.serverId, serverData.userId || null, serverData.expiresAt);
    }

    res.json({
      ok: true,
      data: serverData,
      credentials: {
        username: created.username,
        password: created.password,
        email: created.email,
        domain: created.domain,
      }
    });
  } catch(e) {
    console.error('Create RS Server Error:', e);
    res.json({ ok: false, message: 'Terjadi kesalahan: ' + (e.message || e) });
  }
});

router.get('/api/reseller/servers', resellerAuth, async function(req, res) {
  try {
    var servers = await listRsServersOf(req.resellerUser);
    var result = servers.filter(function(s){ return s.status !== 'deleted'; }).map(function(s) {
      const daysLeft = s.expiresAt ? Math.ceil((s.expiresAt - Date.now()) / 86400000) : null;
      const expired = s.expiresAt ? Date.now() > s.expiresAt : false;
      return Object.assign({}, s, { daysLeft, expired });
    });
    res.json({ ok: true, data: result, total: result.length });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/reseller/servers/:id', resellerAuth, async function(req, res) {
  try {
    var id = req.params.id;
    var r = await getRsServer(id);
    if (!r.data) return res.json({ ok: false, message: 'Server tidak ditemukan.' });
    if (r.data.resellerUsername !== req.resellerUser) return res.status(403).json({ ok: false, message: 'Akses ditolak.' });
    try {
      var details = await getServerDetails(r.data.serverId);
      res.json({ ok: true, data: Object.assign({}, r.data, details, { daysLeft: r.data.expiresAt ? Math.ceil((r.data.expiresAt - Date.now()) / 86400000) : null }) });
    } catch(e) {
      res.json({ ok: true, data: r.data });
    }
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/reseller/servers/:id/extend', resellerAuth, async function(req, res) {
  try {
    var id = req.params.id;
    var addDays = parseInt(req.body.days, 10);
    if (!id || isNaN(addDays) || addDays < 1 || addDays > 3650) return res.json({ ok: false, message: 'Input tidak valid (1–3650 hari).' });
    var r = await getRsServer(id);
    if (!r.data) return res.json({ ok: false, message: 'Server tidak ditemukan.' });
    if (r.data.resellerUsername !== req.resellerUser) return res.status(403).json({ ok: false, message: 'Akses ditolak.' });
    if (r.data.status === 'deleted') return res.json({ ok: false, message: 'Server sudah dihapus, tidak dapat diperpanjang.' });
    var base = (r.data.expiresAt && r.data.expiresAt > Date.now()) ? r.data.expiresAt : Date.now();
    var newExpiry = base + addDays * 86400000;
    if (C.ptero.domain && C.ptero.apikey && r.data.serverId) {
      try { await updateExpiryDescription(r.data.serverId, newExpiry); } catch(e) { console.error('Update Pterodactyl error:', e); }
    }
    await saveRsServer(id, Object.assign({}, r.data, { expiresAt: newExpiry, status: 'active', extendedAt: Date.now(), extendedDays: (r.data.extendedDays || 0) + addDays }), r.sha);
    _gitTreeCache.delete('reseller-servers');
    // ── Re-schedule expiry timer dengan tanggal baru ──────────────────────────
    if (r.data.serverId) require('../lib/event-trigger').triggerRsServerExpiry(id, r.data.serverId, r.data.userId || null, newExpiry);
    auditLog('extend-rs-server', id + ' +' + addDays + 'd', req.ip).catch(function(e) {});
    res.json({ ok: true, newExpiry, newExpiryFmt: new Date(newExpiry).toLocaleDateString('id-ID') });
  } catch(e) {
    console.error('Extend error:', e);
    res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' });
  }
});

router.post('/api/reseller/servers/:id/suspend', resellerAuth, async function(req, res) {
  try {
    var id = req.params.id;
    var r = await getRsServer(id);
    if (!r.data || !r.data.serverId) return res.json({ ok: false, message: 'Server tidak ditemukan.' });
    if (r.data.resellerUsername !== req.resellerUser) return res.status(403).json({ ok: false, message: 'Akses ditolak.' });
    if (r.data.status === 'deleted') return res.json({ ok: false, message: 'Server sudah dihapus.' });
    if (r.data.status === 'suspended') return res.json({ ok: false, message: 'Server sudah dalam status suspended.' });
    try { await suspendServer(r.data.serverId); } catch(e) { return res.json({ ok: false, message: 'Gagal suspend: ' + (e.message || e) }); }
    await saveRsServer(id, Object.assign({}, r.data, { status: 'suspended', _suspendedAt: Date.now() }), r.sha);
    _gitTreeCache.delete('reseller-servers');
    auditLog('suspend-rs-server', id, req.ip).catch(function(){});
    res.json({ ok: true });
  } catch(e) {
    console.error('Suspend error:', e);
    res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' });
  }
});

router.post('/api/reseller/servers/:id/unsuspend', resellerAuth, async function(req, res) {
  try {
    var id = req.params.id;
    var r = await getRsServer(id);
    if (!r.data || !r.data.serverId) return res.json({ ok: false, message: 'Server tidak ditemukan.' });
    if (r.data.resellerUsername !== req.resellerUser) return res.status(403).json({ ok: false, message: 'Akses ditolak.' });
    if (r.data.status === 'deleted') return res.json({ ok: false, message: 'Server sudah dihapus.' });
    try { await unsuspendServer(r.data.serverId); } catch(e) { return res.json({ ok: false, message: 'Gagal unsuspend: ' + (e.message || e) }); }
    await saveRsServer(id, Object.assign({}, r.data, { status: 'active', _unsuspendedAt: Date.now() }), r.sha);
    _gitTreeCache.delete('reseller-servers');
    auditLog('unsuspend-rs-server', id, req.ip).catch(function(){});
    res.json({ ok: true });
  } catch(e) {
    console.error('Unsuspend error:', e);
    res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' });
  }
});

router.delete('/api/reseller/servers/:id', resellerAuth, async function(req, res) {
  try {
    var id = req.params.id;
    var r = await getRsServer(id);
    if (!r.data) return res.json({ ok: false, message: 'Server tidak ditemukan.' });
    if (r.data.resellerUsername !== req.resellerUser) return res.status(403).json({ ok: false, message: 'Akses ditolak.' });
    var srvDeleted = false;
    if (r.data.serverId && C.ptero.domain && C.ptero.apikey) {
      try { await deleteServer(r.data.serverId); srvDeleted = true; } catch(e) { console.error('Delete Pterodactyl error:', e); if (e.response && e.response.status === 404) srvDeleted = true; }
    }
    await saveRsServer(id, Object.assign({}, r.data, { status: 'deleted', _deletedAt: Date.now(), _deletedBy: 'reseller' }), r.sha);
    _gitTreeCache.delete('reseller-servers');
    auditLog('delete-rs-server', id, req.ip).catch(function(){});
    res.json({ ok: true, srvDeleted });
  } catch(e) {
    console.error('Delete error:', e);
    res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' });
  }
});

router.get('/api/admin/resellers', adminAuth, async function(req, res) {
  try {
    var files = await listResellers(); var resellers = [];

    var rsCountMap = {};
    try {
      var rsFiles = (await listDirCached('reseller-servers')).filter(function(f){ return f.name.endsWith('.json'); });
      await Promise.all(rsFiles.map(async function(f) {
        try {
          var rs = await getRsServer(f.name.replace('.json',''));
          if (rs.data && rs.data.resellerUsername && rs.data.status !== 'deleted') {
            rsCountMap[rs.data.resellerUsername] = (rsCountMap[rs.data.resellerUsername] || 0) + 1;
          }
        } catch(e) {}
      }));
    } catch(e) {}
    await Promise.all(files.filter(function(f){ return f.name.endsWith('.json'); }).map(async function(f) {
      try {
        var r = await getReseller(f.name.replace('.json',''));
        if (r.data && !r.data.deleted) resellers.push({
          username: r.data.username, active: r.data.active !== false,
          allowedPlans: r.data.allowedPlans || [], maxServers: r.data.maxServers || 10,
          activeServers: rsCountMap[r.data.username] || 0,
          createdAt: r.data.createdAt, lastLogin: r.data.lastLogin
        });
      } catch(e) {}
    }));
    resellers.sort(function(a,b){ return (b.createdAt||0)-(a.createdAt||0); }); res.json({ ok: true, data: resellers });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/admin/resellers', adminAuth, async function(req, res) {
  try {
    var username = String(req.body.username || '').toLowerCase().trim(); var password = String(req.body.password || '').trim();
    var allowedPlans = Array.isArray(req.body.allowedPlans) ? req.body.allowedPlans.map(function(p){ return String(p).toLowerCase().replace(/[^a-z0-9_]/g,'').slice(0,20); }).filter(Boolean) : [];
    var maxServers = Math.max(1, Math.min(9999, parseInt(req.body.maxServers, 10) || 10));
    if (!isValidResellerUsername(username)) return res.json({ ok: false, message: 'Username tidak valid (3-20 karakter, huruf kecil/angka/_).' });
    if (!password || password.length < 6) return res.json({ ok: false, message: 'Password minimal 6 karakter.' });
    var existing = await getReseller(username); if (existing.data && !existing.data.deleted) return res.json({ ok: false, message: 'Username sudah terdaftar.' });
    var hashed = await hashPassword(password);
    await saveReseller(username, { username, passwordHash: hashed, active: true, allowedPlans, maxServers, createdAt: Date.now(), lastLogin: null }, existing.sha || null);
    _gitTreeCache.delete('resellers'); auditLog('create-reseller', username, req.adminIp).catch(function(){}); res.json({ ok: true });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.patch('/api/admin/resellers/:username', adminAuth, async function(req, res) {
  try {
    var username = req.params.username; if (!isValidResellerUsername(username)) return res.json({ ok: false, message: 'Username tidak valid.' });
    var r = await getReseller(username); if (!r.data || r.data.deleted) return res.json({ ok: false, message: 'Reseller tidak ditemukan.' });
    var updates = { updatedAt: Date.now() };
    if (typeof req.body.active !== 'undefined') updates.active = req.body.active !== false && req.body.active !== 'false';
    if (Array.isArray(req.body.allowedPlans)) updates.allowedPlans = req.body.allowedPlans.map(function(p){ return String(p).toLowerCase().replace(/[^a-z0-9_]/g,'').slice(0,20); }).filter(Boolean);
    if (typeof req.body.maxServers !== 'undefined') { var ms = parseInt(req.body.maxServers, 10); if (!isNaN(ms) && ms >= 1 && ms <= 9999) updates.maxServers = ms; }
    await saveReseller(username, Object.assign({}, r.data, updates), r.sha);
    auditLog('update-reseller', username, req.adminIp).catch(function(){}); res.json({ ok: true });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.delete('/api/admin/resellers/:username', adminAuth, async function(req, res) {
  try {
    var username = req.params.username; if (!isValidResellerUsername(username)) return res.json({ ok: false, message: 'Username tidak valid.' });
    var r = await getReseller(username); if (!r.data) return res.json({ ok: false, message: 'Reseller tidak ditemukan.' });
    await saveReseller(username, Object.assign({}, r.data, { active: false, deleted: true, deletedAt: Date.now() }), r.sha);
    _gitTreeCache.delete('resellers'); auditLog('delete-reseller', username, req.adminIp).catch(function(){}); res.json({ ok: true });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/admin/resellers/:username/reset-password', adminAuth, async function(req, res) {
  try {
    var username = req.params.username; var newPwd = String(req.body.password || '').trim();
    if (!isValidResellerUsername(username)) return res.json({ ok: false, message: 'Username tidak valid.' });
    if (!newPwd || newPwd.length < 6) return res.json({ ok: false, message: 'Password minimal 6 karakter.' });
    var r = await getReseller(username); if (!r.data || r.data.deleted) return res.json({ ok: false, message: 'Reseller tidak ditemukan.' });
    var hashed = await hashPassword(newPwd);
    await saveReseller(username, Object.assign({}, r.data, { passwordHash: hashed, updatedAt: Date.now() }), r.sha);
    auditLog('reset-reseller-pwd', username, req.adminIp).catch(function(){}); res.json({ ok: true });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/admin/reseller-servers', adminAuth, async function(req, res) {
  try {
    var files = [];
    try { files = (await listDirCached('reseller-servers')).filter(function(f){ return f.name.endsWith('.json'); }); } catch(e) {}
    var servers = [];
    await Promise.all(files.map(async function(f) {
      try {
        var r = await getRsServer(f.name.replace('.json',''));
        if (r.data && r.data.status !== 'deleted') {
          var daysLeft = r.data.expiresAt ? Math.ceil((r.data.expiresAt - Date.now()) / 86400000) : null;
          servers.push(Object.assign({}, r.data, { daysLeft, expired: r.data.expiresAt ? Date.now() > r.data.expiresAt : false }));
        }
      } catch(e) {}
    }));
    servers.sort(function(a,b){ return (b.createdAt||0)-(a.createdAt||0); });
    res.json({ ok: true, data: servers, total: servers.length });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/admin/reseller-servers/:id/extend', adminAuth, async function(req, res) {
  try {
    var id = req.params.id; var addDays = parseInt(req.body.days, 10);
    if (!id || isNaN(addDays) || addDays < 1 || addDays > 3650) return res.json({ ok: false, message: 'Input tidak valid (1–3650 hari).' });
    var r = await getRsServer(id); if (!r.data) return res.json({ ok: false, message: 'Server tidak ditemukan.' });
    if (r.data.status === 'deleted') return res.json({ ok: false, message: 'Server sudah dihapus.' });
    var base = (r.data.expiresAt && r.data.expiresAt > Date.now()) ? r.data.expiresAt : Date.now();
    var newExpiry = base + addDays * 86400000;
    if (C.ptero.domain && C.ptero.apikey && r.data.serverId) {
      try { await updateExpiryDescription(r.data.serverId, newExpiry); } catch(e) { console.error('Update Pterodactyl error:', e); }
    }
    await saveRsServer(id, Object.assign({}, r.data, { expiresAt: newExpiry, status: 'active', extendedAt: Date.now(), extendedDays: (r.data.extendedDays || 0) + addDays }), r.sha);
    _gitTreeCache.delete('reseller-servers');
    // ── Re-schedule expiry timer dengan tanggal baru (admin extend) ──────────
    if (r.data.serverId) require('../lib/event-trigger').triggerRsServerExpiry(id, r.data.serverId, r.data.userId || null, newExpiry);
    auditLog('extend-rs-server', id + ' +' + addDays + 'd', req.adminIp).catch(function(e) {});
    res.json({ ok: true, newExpiry, newExpiryFmt: new Date(newExpiry).toLocaleDateString('id-ID') });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/admin/reseller-servers/:id/reduce', adminAuth, async function(req, res) {
  try {
    var id = req.params.id; var reduceDays = parseInt(req.body.days, 10);
    if (!id || isNaN(reduceDays) || reduceDays < 1 || reduceDays > 3650) return res.json({ ok: false, message: 'Input tidak valid.' });
    var r = await getRsServer(id); if (!r.data) return res.json({ ok: false, message: 'Server tidak ditemukan.' });
    var cur = (r.data.expiresAt && r.data.expiresAt > Date.now()) ? r.data.expiresAt : Date.now();
    var newExpiry = Math.max(Date.now(), cur - reduceDays * 86400000);
    if (C.ptero.domain && C.ptero.apikey && r.data.serverId) {
      try { await updateExpiryDescription(r.data.serverId, newExpiry); } catch(e) { console.error('Update Pterodactyl error:', e); }
    }
    await saveRsServer(id, Object.assign({}, r.data, { expiresAt: newExpiry, reducedAt: Date.now(), reducedDays: (r.data.reducedDays||0)+reduceDays }), r.sha);
    _gitTreeCache.delete('reseller-servers');
    res.json({ ok: true, newExpiry, newExpiryFmt: new Date(newExpiry).toLocaleDateString('id-ID') });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/admin/reseller-servers/:id/suspend', adminAuth, async function(req, res) {
  try {
    var id = req.params.id; var r = await getRsServer(id);
    if (!r.data || !r.data.serverId) return res.json({ ok: false, message: 'Server tidak ditemukan.' });
    try { await suspendServer(r.data.serverId); } catch(e) { return res.json({ ok: false, message: 'Gagal suspend: ' + (e.message || e) }); }
    await saveRsServer(id, Object.assign({}, r.data, { status: 'suspended', _suspendedAt: Date.now() }), r.sha);
    auditLog('suspend-rs-server', id, req.adminIp).catch(function(){});
    res.json({ ok: true });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/admin/reseller-servers/:id/unsuspend', adminAuth, async function(req, res) {
  try {
    var id = req.params.id; var r = await getRsServer(id);
    if (!r.data || !r.data.serverId) return res.json({ ok: false, message: 'Server tidak ditemukan.' });
    try { await unsuspendServer(r.data.serverId); } catch(e) { return res.json({ ok: false, message: 'Gagal unsuspend: ' + (e.message || e) }); }
    await saveRsServer(id, Object.assign({}, r.data, { status: 'active', _unsuspendedAt: Date.now() }), r.sha);
    auditLog('unsuspend-rs-server', id, req.adminIp).catch(function(){});
    res.json({ ok: true });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

router.delete('/api/admin/reseller-servers/:id', adminAuth, async function(req, res) {
  try {
    var id = req.params.id; var r = await getRsServer(id);
    if (!r.data) return res.json({ ok: false, message: 'Server tidak ditemukan.' });
    var srvDeleted = false;
    if (r.data.serverId && C.ptero.domain && C.ptero.apikey) {
      try { await deleteServer(r.data.serverId); srvDeleted = true; } catch(e) { console.error('Delete Pterodactyl error:', e); if (e.response && e.response.status === 404) srvDeleted = true; }
    }
    await saveRsServer(id, Object.assign({}, r.data, { status: 'deleted', _deletedAt: Date.now(), _deletedBy: 'admin' }), r.sha);
    _gitTreeCache.delete('reseller-servers'); auditLog('delete-rs-server', id, req.adminIp).catch(function(){});
    res.json({ ok: true, srvDeleted });
  } catch(e) { console.error('[reseller] error:', e.message || e); res.json({ ok: false, message: e.message || 'Terjadi kesalahan, coba lagi.' }); }
});

module.exports = router;
