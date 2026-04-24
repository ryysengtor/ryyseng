'use strict';

const express = require('express');
const axios   = require('axios');
const QRCode  = require('qrcode');
const crypto  = require('crypto');
const router  = express.Router();

const { rateLimit }  = require('../lib/auth');
const { dbRead }     = require('../lib/db');
const {
  getUser, saveUser, listUsers, getDeposit, saveDeposit, listDirCached,
  isValidUsername, updateBalance, hashPassword, verifyPassword, newId, _sleep,
} = require('../lib/models');
const { userAuth, makeUserToken }  = require('../lib/user-auth');
const { broadcastAdmin }           = require('../lib/broadcast');
const { triggerDepositWatch }      = require('../lib/event-trigger');
const rotp = require('../lib/rotp');
const C    = require('../lib/config');

router.post('/api/user/register', async function(req, res) {
  try {
    const ip  = req.ip || 'x';
    if (!rateLimit('ureg:' + ip, 5, 30 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak percobaan registrasi.' });
    await new Promise(function(r){ setTimeout(r, 60 + Math.random() * 80); });
    const username = String(req.body.username || '').toLowerCase().trim();
    const password = String(req.body.password || '');
    const email    = String(req.body.email || '').trim().slice(0, 100);
    if (!isValidUsername(username)) return res.json({ ok: false, message: 'Username 3–20 karakter, hanya huruf kecil, angka, dan underscore.' });
    if (!password || password.length < 6)  return res.json({ ok: false, message: 'Password minimal 6 karakter.' });
    if (password.length > 72) return res.json({ ok: false, message: 'Password terlalu panjang.' });
    const existing = await getUser(username);
    if (existing.data) return res.json({ ok: false, message: 'Username sudah dipakai.' });
    const hashed = await hashPassword(password);
    const now    = Date.now();
    await saveUser(username, { username, passwordHash: hashed, email: email || null, balance: 0, createdAt: now, lastLogin: null }, null);
    console.log('[user] register:', username, '| ip:', ip);
    res.json({ ok: true, message: 'Akun berhasil dibuat. Silakan login.' });
  } catch(e) { console.error('[register]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/user/login', async function(req, res) {
  try {
    const ip  = req.ip || 'x';
    if (!rateLimit('ulog:' + ip, 8, 15 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak percobaan login. Coba lagi 15 menit.' });
    await new Promise(function(r){ setTimeout(r, 80 + Math.random() * 120); });
    const username = String(req.body.username || '').toLowerCase().trim();
    const password = String(req.body.password || '');
    if (!isValidUsername(username) || !password) return res.json({ ok: false, message: 'Username atau password salah.' });

    if (!rateLimit('ulog-un:' + username, 10, 15 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak percobaan login untuk akun ini. Coba lagi 15 menit.' });
    const r = await getUser(username);
    if (!r.data) return res.json({ ok: false, message: 'Username atau password salah.' });
    if (r.data.banned) return res.json({ ok: false, message: 'Akun diblokir. Hubungi admin.' });
    const valid = await verifyPassword(password, r.data.passwordHash);
    if (!valid) { console.warn('[user] login gagal:', username, '| ip:', ip); return res.json({ ok: false, message: 'Username atau password salah.' }); }
    const token = makeUserToken(username);
    await saveUser(username, Object.assign({}, r.data, { lastLogin: Date.now() }), r.sha);
    console.log('[user] login:', username, '| ip:', ip);
    res.json({ ok: true, token, username });
  } catch(e) { console.error('[login]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/user/logout', function(req, res) { res.json({ ok: true }); });

router.get('/api/user/google-clientid', function(req, res) {
  var clientId = process.env.GOOGLE_CLIENT_ID || '';
  res.json({ ok: true, clientId, enabled: !!clientId });
});

router.post('/api/user/google-login', async function(req, res) {
  try {
    const ip = req.ip || 'x';
    if (!rateLimit('uglogin:' + ip, 10, 15 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak percobaan. Coba lagi 15 menit.' });
    const credential = String(req.body.credential || '');
    if (!credential || credential.length > 4096) return res.json({ ok: false, message: 'Token Google tidak valid.' });
    const clientId = process.env.GOOGLE_CLIENT_ID || '';
    if (!clientId) return res.json({ ok: false, message: 'Login Google belum dikonfigurasi.' });
    const verifyRes = await axios.get('https://oauth2.googleapis.com/tokeninfo', { params: { id_token: credential }, timeout: 10000 });
    const info = verifyRes.data;
    if (info.aud !== clientId) return res.json({ ok: false, message: 'Token Google tidak valid.' });
    const googleSub = String(info.sub || '').trim();
    const googleEmail = String(info.email || '').toLowerCase().trim();
    const emailVerified = info.email_verified === true || info.email_verified === 'true';
    if (!googleSub || !googleEmail || !emailVerified) return res.json({ ok: false, message: 'Email Google belum terverifikasi.' });
    const files = await listUsers();
    let found = null;
    for (var fi = 0; fi < files.length; fi++) {
      const fname = (files[fi].name || files[fi] || '').replace('.json', '');
      if (!fname) continue;
      const ur = await getUser(fname);
      if (ur.data && ur.data.googleSub && ur.data.googleSub === googleSub) { found = { username: fname, data: ur.data, sha: ur.sha }; break; }
    }
    if (!found) {
      let baseUser = googleEmail.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^_+|_+$/g, '').replace(/_+/g, '_').slice(0, 16);
      if (baseUser.length < 3) baseUser = ('g_' + baseUser + '_usr').slice(0, 16);
      if (/^[0-9]/.test(baseUser)) baseUser = 'u_' + baseUser.slice(0, 14);
      let finalUser = baseUser;
      for (var attempt = 0; attempt < 5; attempt++) {
        if (attempt > 0) { const suffix = '_' + Math.floor(1000 + Math.random() * 9000); finalUser = baseUser.slice(0, 20 - suffix.length) + suffix; }
        if (!isValidUsername(finalUser)) continue;
        const existing = await getUser(finalUser);
        if (!existing.data) break;
        if (attempt === 4) finalUser = 'g_' + crypto.randomBytes(4).toString('hex');
      }
      if (!isValidUsername(finalUser)) return res.json({ ok: false, message: 'Gagal membuat akun. Coba lagi.' });
      const now = Date.now();
      await saveUser(finalUser, { username: finalUser, passwordHash: null, email: googleEmail, googleSub, balance: 0, createdAt: now, lastLogin: now }, null);
      console.log('[user] google-register:', finalUser, googleEmail, '| ip:', ip);
      return res.json({ ok: true, token: makeUserToken(finalUser), username: finalUser, isNew: true });
    }
    if (found.data.banned) return res.json({ ok: false, message: 'Akun diblokir. Hubungi admin.' });
    await saveUser(found.username, Object.assign({}, found.data, { lastLogin: Date.now() }), found.sha);
    console.log('[user] google-login:', found.username, googleEmail, '| ip:', ip);
    res.json({ ok: true, token: makeUserToken(found.username), username: found.username, isNew: false });
  } catch(e) {
    if (e.response && e.response.status === 400) return res.json({ ok: false, message: 'Token Google tidak valid atau sudah kadaluarsa.' });
    console.error('[google-login]', e.message);
    res.json({ ok: false, message: 'Gagal verifikasi Google: ' + 'Hubungi admin jika masalah berlanjut.' });
  }
});

router.get('/api/user/me', userAuth, async function(req, res) {
  try {
    const r = await getUser(req.user);
    if (!r.data) return res.json({ ok: false, message: 'User tidak ditemukan.' });
    if (r.data.banned) return res.json({ ok: false, banned: true, message: 'Akun kamu telah diblokir oleh admin.' });
    res.json({ ok: true, data: { username: r.data.username, balance: r.data.balance || 0, email: r.data.email, createdAt: r.data.createdAt } });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/user/change-password', userAuth, async function(req, res) {
  if (!rateLimit('chgpwd:' + req.user, 5, 15 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.' });
  try {
    const oldPwd = String(req.body.oldPassword || '');
    const newPwd = String(req.body.newPassword || '');
    if (!newPwd || newPwd.length < 6) return res.json({ ok: false, message: 'Password baru minimal 6 karakter.' });
    if (newPwd.length > 72) return res.json({ ok: false, message: 'Password terlalu panjang.' });
    const r = await getUser(req.user);
    if (!r.data) return res.json({ ok: false, message: 'User tidak ditemukan.' });
    const valid = await verifyPassword(oldPwd, r.data.passwordHash);
    if (!valid) return res.json({ ok: false, message: 'Password lama salah.' });
    const hashed = await hashPassword(newPwd);
    await saveUser(req.user, Object.assign({}, r.data, { passwordHash: hashed, updatedAt: Date.now(), lastTokenReset: Date.now() }), r.sha);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

var _depCreateLocks = new Map();

router.post('/api/deposit/create', userAuth, async function(req, res) {
  // BUG FIX: Lock sebelumnya dibersihkan secara manual di tiap titik return,
  // berisiko stuck jika ada exception tak terduga. Gunakan try/finally agar
  // lock SELALU dilepas, apapun yang terjadi.
  const ip = req.ip || 'x';
  if (!rateLimit('dep:' + req.user, 5, 15 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak deposit. Tunggu sebentar.' });
  if (_depCreateLocks.has(req.user)) return res.status(429).json({ ok: false, message: 'Sedang membuat deposit, harap tunggu...' });
  _depCreateLocks.set(req.user, Date.now());
  try {
    const amount = parseInt(req.body.amount, 10);
    const { getEffectiveSettings } = require('../lib/models');
    const stg = await getEffectiveSettings();
    const depFeeType = stg.depositFeeType || 'flat';
    const depFeeVal  = stg.depositFee  || 0;
    const depMin     = stg.depositMin  || 1000;
    if (!amount || amount < depMin) return res.json({ ok: false, message: 'Minimum deposit ' + depMin.toLocaleString('id-ID') + '.' });
    if (amount > 10000000) return res.json({ ok: false, message: 'Maksimum deposit Rp10.000.000 sekali transaksi.' });

    try {
      const depListR = await listDirCached('deposits');
      const depFiles = Array.isArray(depListR) ? depListR.filter(function(f){ return f.name.endsWith('.json'); }) : [];
      for (var df = 0; df < depFiles.length; df++) {
        try {
          const existR = await getDeposit(depFiles[df].name.replace('.json', ''));
          if (!existR.data) continue;
          if (existR.data.username !== req.user || existR.data.status !== 'pending') continue;
          if (existR.data.expiredAt && Date.now() > existR.data.expiredAt) continue;
          if (existR.data.amount !== amount) continue;
          let _resumeQr = existR.data.qrImage || null;
          if (!_resumeQr && existR.data.qrString) {
            try { _resumeQr = await QRCode.toDataURL(existR.data.qrString, { errorCorrectionLevel: 'M', margin: 2, scale: 8, color: { dark: '#000000', light: '#ffffff' } }); } catch(e) {}
          }
          return res.json({ ok: true, depId: existR.data.id, qr: _resumeQr, qrString: existR.data.qrString || null, expiredAt: existR.data.expiredAt, amount: existR.data.amount, adminFeeDeposit: existR.data.adminFeeDeposit || 0, totalBayarDeposit: existR.data.totalBayarDeposit || existR.data.amount, resumed: true });
        } catch(e) {}
      }
    } catch(e) {}

    const adminFeeDeposit = depFeeType === 'percent' ? Math.round(amount * depFeeVal / 100) : Math.round(depFeeVal);
    const totalBayarDeposit = amount + adminFeeDeposit;
    let rotpData;
    try {
      const r = await rotp.depositCreate(totalBayarDeposit);
      if (!r.success) throw new Error((r.error && r.error.message) || 'Deposit gagal');
      rotpData = r.data;
    } catch(e) { return res.json({ ok: false, message: 'Gagal buat deposit. Hubungi admin.' }); }

    const _rotpExpRaw = rotpData.expired_at_ts || rotpData.expired || null;
    const rotpExpiry  = _rotpExpRaw ? (_rotpExpRaw > 1e12 ? _rotpExpRaw : _rotpExpRaw * 1000) : (Date.now() + 20 * 60 * 1000);
    const rotpQrImg   = rotpData.qr_image || rotpData.qr || null;
    const rotpQrStr   = rotpData.qr_string || null;
    let qrImageFinal  = rotpQrImg;
    if (rotpQrImg && rotpQrImg.startsWith('http')) {
      try {
        const qrResp = await axios.get(rotpQrImg, { responseType: 'arraybuffer', timeout: 8000, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; QRProxy/1.0)' }, maxContentLength: 1 * 1024 * 1024 });
        const qrCt = (qrResp.headers['content-type'] || 'image/png').split(';')[0].trim();
        qrImageFinal = 'data:' + qrCt + ';base64,' + Buffer.from(qrResp.data).toString('base64');
      } catch(qrErr) {
        if (rotpQrStr) { try { qrImageFinal = await QRCode.toDataURL(rotpQrStr, { errorCorrectionLevel: 'M', margin: 2, scale: 8, color: { dark: '#000000', light: '#ffffff' } }); } catch(e) {} }
      }
    }
    const depId = 'DEP-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
    const now   = Date.now();
    const expiredAt = Math.min(rotpExpiry, now + 20 * 60 * 1000);

    const dep = { id: depId, username: req.user, rotpId: rotpData.id, amount, adminFeeDeposit, totalBayarDeposit, qrString: rotpQrStr || null, qrImage: qrImageFinal || null, status: 'pending', expiredAt, createdAt: now };
    await saveDeposit(depId, dep, null);
    console.log('[deposit] create:', depId, '| user:', req.user, '| saldo Rp' + amount, '| fee Rp' + adminFeeDeposit, '| total bayar Rp' + totalBayarDeposit);

    // ── Jadwalkan per-item deposit watch langsung setelah deposit dibuat ──────
    triggerDepositWatch(depId);

    res.json({ ok: true, depId, qr: qrImageFinal, qrString: rotpQrStr, expiredAt, amount, adminFeeDeposit, totalBayarDeposit });
  } catch(e) { console.error('[deposit/create]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
  finally {
    // BUG FIX: Lock selalu dilepas di finally, mencegah user terjebak
    // tidak bisa deposit lagi jika ada error yang tidak tertangkap
    _depCreateLocks.delete(req.user);
  }
});

router.get('/api/deposit/status/:id', userAuth, async function(req, res) {
  try {
    const depId = req.params.id;
    const { isValidDepId } = require('../lib/models');
    if (!isValidDepId(depId)) return res.json({ ok: false, message: 'ID tidak valid.' });
    if (!rateLimit('dsc:' + depId, 60, 10 * 60 * 1000)) return res.json({ ok: false, status: 'pending' });
    if (!rateLimit('dsc-user:' + req.user, 200, 10 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    const r   = await getDeposit(depId);
    if (!r.data) return res.json({ ok: false, message: 'Deposit tidak ditemukan.' });
    if (r.data.username !== req.user) return res.status(403).json({ ok: false, message: 'Akses ditolak.' });
    const dep = r.data;
    if (dep.status === 'success')   return res.json({ ok: true, status: 'success', balance: dep.creditedBalance });
    if (dep.status === 'cancel')    return res.json({ ok: true, status: 'cancel' });
    if (dep.status === 'crediting') return res.json({ ok: true, status: 'pending' });

    if (dep.expiredAt && Date.now() > dep.expiredAt) {
      let rotpStatusCheck = null;
      try { const srCheck = await rotp.depositStatus(dep.rotpId); rotpStatusCheck = (srCheck && srCheck.success && srCheck.data) ? srCheck.data.status : null; } catch(e) {}
      if (rotpStatusCheck === 'success') {
        try {
          const freshLockLate = await getDeposit(depId);
          if (!freshLockLate.data) return res.json({ ok: false, message: 'Deposit tidak ditemukan.' });
          if (freshLockLate.data.status === 'success') return res.json({ ok: true, status: 'success', balance: freshLockLate.data.creditedBalance });
          if (freshLockLate.data.status === 'crediting') return res.json({ ok: true, status: 'pending' });

          await saveDeposit(depId, Object.assign({}, freshLockLate.data, { status: 'crediting', creditingAt: Date.now(), balanceCredited: true }), freshLockLate.sha);
        } catch(lockErrLate) { return res.json({ ok: true, status: 'pending' }); }
        let newBal;
        try { newBal = await updateBalance(req.user, dep.amount); }
        catch(balErrLate) {

          const freshFailLate = await getDeposit(depId).catch(function(){ return { data: dep, sha: null }; });
          await saveDeposit(depId, Object.assign({}, freshFailLate.data || dep, { status: 'pending', creditingAt: null, balanceCredited: false }), freshFailLate.sha || null).catch(function(){});
          return res.json({ ok: false, message: 'Gagal memperbarui saldo. Coba lagi.' });
        }
        const freshLateDone = await getDeposit(depId).catch(function(){ return { data: dep, sha: null }; });
        await saveDeposit(depId, Object.assign({}, freshLateDone.data || dep, { status: 'success', paidAt: Date.now(), creditedBalance: newBal, latePaymentDetected: true }), freshLateDone.sha || null);
        broadcastAdmin({ type: 'deposit_success', id: depId, username: req.user, amount: dep.amount, ts: Date.now() });
        return res.json({ ok: true, status: 'success', balance: newBal });
      }
      const gracePeriod = 3 * 60 * 1000;
      if (rotpStatusCheck === 'cancel' || Date.now() > dep.expiredAt + gracePeriod) {
        try { await rotp.depositCancel(dep.rotpId); } catch(e) {}
        const freshCancel = await getDeposit(depId).catch(function(){ return { data: dep, sha: r.sha }; });
        if (freshCancel.data && (freshCancel.data.status === 'success' || freshCancel.data.status === 'crediting')) return res.json({ ok: true, status: freshCancel.data.status === 'success' ? 'success' : 'pending', balance: freshCancel.data.creditedBalance });
        if (freshCancel.data && freshCancel.data.status === 'cancel') return res.json({ ok: true, status: 'cancel', message: 'Deposit kadaluarsa.' });
        await saveDeposit(depId, Object.assign({}, freshCancel.data || dep, { status: 'cancel', cancelledAt: Date.now(), expiredAuto: true }), freshCancel.sha || r.sha);
        return res.json({ ok: true, status: 'cancel', message: 'Deposit kadaluarsa.' });
      }
      return res.json({ ok: true, status: 'pending' });
    }

    let rotpStatus;
    try { const sr = await rotp.depositStatus(dep.rotpId); rotpStatus = sr.success && sr.data ? sr.data.status : 'pending'; }
    catch(e) { return res.json({ ok: true, status: 'pending' }); }

    if (rotpStatus === 'success') {
      try {
        const freshLock = await getDeposit(depId);
        if (!freshLock.data) return res.json({ ok: false, message: 'Deposit tidak ditemukan.' });
        if (freshLock.data.status === 'success') return res.json({ ok: true, status: 'success', balance: freshLock.data.creditedBalance });
        if (freshLock.data.status === 'crediting') return res.json({ ok: true, status: 'pending' });
        if (freshLock.data.status === 'cancel') return res.json({ ok: true, status: 'cancel' });

        await saveDeposit(depId, Object.assign({}, freshLock.data, { status: 'crediting', creditingAt: Date.now(), balanceCredited: true }), freshLock.sha);
      } catch(lockErr) { return res.json({ ok: true, status: 'pending' }); }
      let newBal;
      try { newBal = await updateBalance(req.user, dep.amount); }
      catch(balErr) {

        const freshFail = await getDeposit(depId).catch(function(){ return { data: dep, sha: null }; });
        await saveDeposit(depId, Object.assign({}, freshFail.data || dep, { status: 'pending', creditingAt: null, balanceCredited: false }), freshFail.sha || null).catch(function(){});
        return res.json({ ok: false, message: 'Gagal memperbarui saldo. Coba lagi.' });
      }
      const freshOk = await getDeposit(depId).catch(function(){ return { data: dep, sha: null }; });
      await saveDeposit(depId, Object.assign({}, freshOk.data || dep, { status: 'success', paidAt: Date.now(), creditedBalance: newBal }), freshOk.sha || null);
      broadcastAdmin({ type: 'deposit_success', id: depId, username: req.user, amount: dep.amount, ts: Date.now() });
      return res.json({ ok: true, status: 'success', balance: newBal });
    }
    if (rotpStatus === 'cancel') { await saveDeposit(depId, Object.assign({}, dep, { status: 'cancel', cancelledAt: Date.now() }), r.sha); return res.json({ ok: true, status: 'cancel' }); }
    res.json({ ok: true, status: 'pending' });
  } catch(e) { console.error('[deposit/status]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/deposit/list', userAuth, async function(req, res) {
  try {
    let deps = [];
    try {
      const r = await listDirCached('deposits');
      const files = Array.isArray(r) ? r.filter(function(f){ return f.name.endsWith('.json'); }) : [];
      await Promise.all(files.map(async function(f) {
        try {
          const d = await getDeposit(f.name.replace('.json',''));
          if (d.data && d.data.username === req.user) deps.push({ id: d.data.id, amount: d.data.amount, adminFeeDeposit: d.data.adminFeeDeposit || 0, totalBayarDeposit: d.data.totalBayarDeposit || d.data.amount, status: d.data.status, createdAt: d.data.createdAt, expiredAt: d.data.expiredAt || null, qrImage: (d.data.status === 'pending') ? (d.data.qrImage || null) : null });
        } catch(e) {}
      }));
    } catch(e) {}
    deps.sort(function(a,b){ return (b.createdAt||0)-(a.createdAt||0); });
    res.json({ ok: true, data: deps.slice(0, 30) });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/deposit/cancel/:id', userAuth, async function(req, res) {
  try {
    const depId = req.params.id;
    const { isValidDepId } = require('../lib/models');
    if (!isValidDepId(depId)) return res.json({ ok: false, message: 'ID tidak valid.' });
    if (!rateLimit('depcancel:' + req.user, 3, 30 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak permintaan.' });
    const r = await getDeposit(depId);
    if (!r.data) return res.json({ ok: false, message: 'Deposit tidak ditemukan.' });
    if (r.data.username !== req.user) return res.status(403).json({ ok: false, message: 'Akses ditolak.' });
    if (r.data.status !== 'pending') return res.json({ ok: false, message: 'Deposit sudah ' + r.data.status + ', tidak bisa dibatalkan.' });
    try {
      const srCheck = await rotp.depositStatus(r.data.rotpId);
      if (srCheck && srCheck.success && srCheck.data && srCheck.data.status === 'success') return res.json({ ok: false, message: 'Pembayaran sudah diterima. Refresh halaman untuk lihat saldo.' });
    } catch(e) {}
    try { await rotp.depositCancel(r.data.rotpId); } catch(e) {}
    await saveDeposit(depId, Object.assign({}, r.data, { status: 'cancel', cancelledAt: Date.now() }), r.sha);
    res.json({ ok: true });
  } catch(e) {
    if (e.response && e.response.status === 409) return res.json({ ok: false, message: 'Konflik permintaan, coba lagi.' });
    res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' });
  }
});

module.exports = router;
