'use strict';

const express = require('express');
const crypto  = require('crypto');
const router  = express.Router();

const { rateLimit, adminAuth }     = require('../lib/auth');
const { _acquireOtpLockDB, _releaseOtpLockDB, dbRead } = require('../lib/db');
const {
  getOtpOrder, saveOtpOrder, listOtpOrders,
  getUser, updateBalance, idrFormat, isValidOtpId, getEffectiveSettings,
} = require('../lib/models');
const { userAuth }      = require('../lib/user-auth');
const { broadcastAdmin } = require('../lib/broadcast');
const rotp              = require('../lib/rotp');

var _svcCache = { data: null, ts: 0 };

var _rotpBalCache = { val: null, ts: 0 };
var _otpLastOrderTime = new Map();
const _OTP_ORDER_COOLDOWN_MS = 3000;

function _checkOtpCooldown(username) {
  var last = _otpLastOrderTime.get(username) || 0;
  var diff = Date.now() - last;
  return diff < _OTP_ORDER_COOLDOWN_MS ? _OTP_ORDER_COOLDOWN_MS - diff : 0;
}

router.get('/api/otp/services', async function(req, res) {
  try {
    if (!rateLimit('otpsvc:' + (req.ip||'x'), 60, 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });

    var _rotpKey = require('../lib/config').otp.apikey;
    if (!_rotpKey) return res.json({ ok: false, message: 'RUMAHOTP_APIKEY belum dikonfigurasi. Set environment variable RUMAHOTP_APIKEY di Vercel/server.' });
    if (_svcCache.data && Date.now() - _svcCache.ts < 10 * 60 * 1000) {
      const pinnedR = await dbRead('otp-pinned.json').catch(function(){ return {data:[]}; });
      return res.json({ ok: true, data: _svcCache.data, pinned: pinnedR.data || [] });
    }
    let r;
    try { r = await rotp.services(); } catch(e) {
      if (_svcCache.data) { const pr3 = await dbRead('otp-pinned.json').catch(function(){ return {data:[]}; }); return res.json({ ok: true, data: _svcCache.data, pinned: pr3.data || [], stale: true }); }
      return res.json({ ok: false, message: 'RumahOTP tidak dapat dihubungi: ' + e.message });
    }
    if (r.success && Array.isArray(r.data) && r.data.length > 0) {
      _svcCache.data = r.data; _svcCache.ts = Date.now();
      const pinnedR2 = await dbRead('otp-pinned.json').catch(function(){ return {data:[]}; });
      return res.json({ ok: true, data: r.data, pinned: pinnedR2.data || [] });
    }
    if (_svcCache.data) { const pr4 = await dbRead('otp-pinned.json').catch(function(){ return {data:[]}; }); return res.json({ ok: true, data: _svcCache.data, pinned: pr4.data || [], stale: true }); }
    var _errMsg = (r.error && r.error.message) || 'Gagal mengambil daftar layanan dari RumahOTP.';

    if (typeof _errMsg === 'string' && (_errMsg.toLowerCase().includes('api key') || _errMsg.toLowerCase().includes('unauthorized') || _errMsg.toLowerCase().includes('invalid'))) {
      _errMsg = 'API key RumahOTP tidak valid. Periksa nilai RUMAHOTP_APIKEY.';
    }
    res.json({ ok: false, message: _errMsg });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan: ' + e.message }); }
});

router.get('/api/otp/pinned', async function(req, res) {
  try { const r = await dbRead('otp-pinned.json'); res.json({ ok: true, data: r.data || [] }); } catch(e) { res.json({ ok: true, data: [] }); }
});

router.get('/api/otp/operators/:country/:providerId', async function(req, res) {
  try {
    if (!rateLimit('otpops:' + (req.ip||'x'), 60, 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    const country    = String(req.params.country    || '').trim().slice(0, 100);
    const providerId = String(req.params.providerId || '').trim().slice(0, 100);
    if (!country || !providerId) return res.json({ ok: false, message: 'Parameter tidak lengkap.' });
    let r;
    try { r = await rotp.operators(country, providerId); } catch(e) {
      return res.json({ ok: false, message: 'RumahOTP tidak dapat dihubungi: ' + e.message });
    }
    if (!r.success || !Array.isArray(r.data)) {
      return res.json({ ok: false, message: (r.error && r.error.message) || 'Gagal mengambil daftar operator.' });
    }
    res.json({ ok: true, data: r.data });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/otp/countries/:serviceId', async function(req, res) {
  try {
    if (!rateLimit('otpcnt:' + (req.ip||'x'), 60, 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    const sid = String(req.params.serviceId || '').trim();
    if (!sid || sid.length > 100 || !/^[a-zA-Z0-9_\-]+$/.test(sid)) return res.json({ ok: false, message: 'Service ID tidak valid.' });

    let r;
    try { r = await rotp.countries(sid); } catch(e) {
      return res.json({ ok: false, message: 'RumahOTP tidak dapat dihubungi: ' + e.message });
    }
    if (!r.success || !Array.isArray(r.data)) { return res.json({ ok: false, message: (r.error && r.error.message) || 'Gagal mengambil daftar negara.' }); }
    const _stgOtp = await getEffectiveSettings(); const _otpMk = _stgOtp.otpMarkup || 0;
    const data = r.data.map(function(c) { return Object.assign({}, c, { pricelist: (c.pricelist || []).map(function(p) { return Object.assign({}, p, { price: p.price + _otpMk, price_format: idrFormat(p.price + _otpMk) }); }) }); });
    res.json({ ok: true, data });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/otp/info', async function(req, res) {
  try {
    const s = await getEffectiveSettings();
    res.json({ ok: true, settings: { depositFeeType: s.depositFeeType, depositFee: s.depositFee, depositMin: s.depositMin, storeName: s.storeName, wa: s.wa, otpEnabled: s.otpEnabled } });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/otp/provider-balance', userAuth, async function(req, res) {
  try {
    if (Date.now() - _rotpBalCache.ts < 60000 && _rotpBalCache.val !== null) return res.json({ ok: true, data: _rotpBalCache.val });
    const r = await rotp.balance();
    if (r.success) { _rotpBalCache.val = r.data.balance; _rotpBalCache.ts = Date.now(); }
    res.json({ ok: r.success, data: r.data ? r.data.balance : 0 });
  } catch(e) { res.json({ ok: false, data: 0 }); }
});

router.post('/api/otp/order', userAuth, async function(req, res) {
  if (!rateLimit('otpord:' + req.user, 10, 5 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak order. Tunggu sebentar.' });
  var _orderStart = Date.now();
  var _lockHandle = null;
  try {

    try {
      _lockHandle = await _acquireOtpLockDB(req.user);
    } catch(lockErr) {
      return res.status(429).json({ ok: false, message: lockErr.message || 'User sedang memproses order lain. Tunggu sebentar.' });
    }


    const _cooldownLeft = _checkOtpCooldown(req.user);
    if (_cooldownLeft > 0) return res.status(429).json({ ok: false, message: 'Terlalu cepat. Tunggu ' + Math.ceil(_cooldownLeft / 1000) + ' detik sebelum order lagi.' });
    const number_id    = parseInt(req.body.number_id, 10);
    const provider_id  = String(req.body.provider_id || '').trim();
    const operator_id  = String(req.body.operator_id || 'any').trim();
    const price        = parseInt(req.body.price, 10);
    const service_name = String(req.body.service_name || '').slice(0, 100);
    const country_name = String(req.body.country_name || '').slice(0, 100);
    if (!number_id || !provider_id || !price) return res.json({ ok: false, message: 'Data tidak lengkap.' });
    const _minOtpPrice = 100; const _maxOtpPrice = 500000;
    if (price < _minOtpPrice || price > _maxOtpPrice) return res.json({ ok: false, message: 'Harga tidak valid. Refresh halaman dan coba lagi.' });
    const service_id = String(req.body.service_id || '').trim().slice(0, 100);
    if (!service_id || !/^[a-zA-Z0-9_\-]{1,100}$/.test(service_id)) return res.json({ ok: false, message: 'service_id tidak valid. Refresh dan coba lagi.' });

    let _stgOtpOrder, _cntVerifyResult, _userBanResult;
    try {
      [_stgOtpOrder, _cntVerifyResult, _userBanResult] = await Promise.all([
        getEffectiveSettings().then(function(s){ return s.otpMarkup || 0; }),
        rotp.countries(service_id),
        getUser(req.user).catch(function(){ return null; })
      ]);
    } catch(_parallelErr) {
      return res.json({ ok: false, message: 'Gagal verifikasi harga. Coba lagi.' });
    }

    if (_userBanResult && _userBanResult.data && _userBanResult.data.banned) {
      return res.status(403).json({ ok: false, message: 'Akun diblokir. Hubungi admin.' });
    }

    let finalPrice = null;
    if (_cntVerifyResult.success && Array.isArray(_cntVerifyResult.data)) {

      outer: for (const _c of _cntVerifyResult.data) {
        if (!Array.isArray(_c.pricelist)) continue;
        for (const _pl of _c.pricelist) {
          if (_c.number_id === number_id && String(_pl.provider_id) === String(provider_id)) {
            finalPrice = _pl.price + _stgOtpOrder; break outer;
          }
        }
      }

      if (finalPrice === null) {
        outer2: for (const _c of _cntVerifyResult.data) {
          if (_c.number_id !== number_id || !Array.isArray(_c.pricelist)) continue;

          const _avail = _c.pricelist.find(function(p) { return p.available && p.stock > 0; });
          if (_avail) { finalPrice = _avail.price + _stgOtpOrder; break outer2; }
        }
      }
    }
    if (finalPrice === null) return res.json({ ok: false, message: 'Harga tidak dapat diverifikasi. Refresh halaman dan coba lagi.' });
    if (Math.abs(price - finalPrice) / finalPrice > 0.05) return res.json({ ok: false, message: 'Harga berubah. Refresh halaman dan coba lagi.' });
    if (!rateLimit('otpbuy:' + req.user + ':' + number_id + ':' + provider_id, 1, 5 * 1000)) return res.status(429).json({ ok: false, message: 'Permintaan terlalu cepat. Tunggu sebentar.' });
    let newBal;
    try { newBal = await updateBalance(req.user, -finalPrice); } catch(balErr) { return res.json({ ok: false, message: balErr.message }); }
    _otpLastOrderTime.set(req.user, Date.now());
    let rotpOrder;
    try {
      const r = await rotp.order(number_id, provider_id, operator_id);
      if (!r.success) throw new Error((r.error && r.error.message) || 'Gagal order nomor');
      rotpOrder = r.data;
    } catch(e) {
      try { await updateBalance(req.user, +finalPrice); } catch(rbErr) { console.error('[otp/order] ROLLBACK GAGAL:', rbErr.message); }
      return res.json({ ok: false, message: 'RumahOTP: ' + e.message });
    }
    const ordId = 'OTP-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
    const now   = Date.now();

    const _expiresAt = rotpOrder.expired_at ? Number(rotpOrder.expired_at) : Date.now() + (rotpOrder.expires_in_minute || 15) * 60000;
    const order = { id: ordId, username: req.user, rotpOrderId: rotpOrder.order_id, phoneNumber: rotpOrder.phone_number, service: service_name || rotpOrder.service, country: country_name || rotpOrder.country, operator: rotpOrder.operator, price: finalPrice, priceRoTP: finalPrice - (_stgOtpOrder || 0), status: 'waiting', otp: null, expiresAt: _expiresAt, createdAt: now };
    try { await saveOtpOrder(ordId, order, null); }
    catch(saveErr) {
      try { await rotp.cancelOrder(rotpOrder.order_id); } catch(e) {}
      try { await updateBalance(req.user, +finalPrice); } catch(rbErr) { console.error('[otp/order] ROLLBACK GAGAL:', rbErr.message); }
      return res.json({ ok: false, message: 'Gagal menyimpan order. Saldo sudah dikembalikan. Coba lagi.' });
    }
    broadcastAdmin({ type: 'new_otp_order', id: ordId, username: req.user, service: order.service, country: order.country, price: finalPrice, phone: rotpOrder.phone_number || '', ts: Date.now() });

    // ── Event-driven: mulai background watcher per-OTP-order ─────────────────
    // Auto-expire + refund saldo saat waktu habis, tanpa butuh cron global
    require('../lib/event-trigger').triggerOtpOrderWatch(ordId);

    res.json({ ok: true, orderId: ordId, phoneNumber: rotpOrder.phone_number, expiresAt: order.expiresAt, balance: newBal });
  } catch(e) { console.error('[otp/order]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
  finally { await _releaseOtpLockDB(_lockHandle).catch(function(){}); }
});

router.get('/api/otp/order/:id/status', userAuth, async function(req, res) {
  try {
    const ordId = req.params.id;
    if (!isValidOtpId(ordId)) return res.json({ ok: false, message: 'ID tidak valid.' });
    if (!rateLimit('otpchk:' + ordId, 40, 10 * 60 * 1000)) return res.json({ ok: true, status: 'waiting' });
    if (!rateLimit('otpchk-user:' + req.user, 150, 10 * 60 * 1000)) return res.json({ ok: true, status: 'waiting' });
    const r   = await getOtpOrder(ordId);
    if (!r.data) return res.json({ ok: false, message: 'Order tidak ditemukan.' });
    if (r.data.username !== req.user) return res.status(403).json({ ok: false, message: 'Akses ditolak.' });
    const ord = r.data;
    if (['completed','canceled','expired'].includes(ord.status)) return res.json({ ok: true, status: ord.status, otp: ord.otp, refunded: ord.refunded || false, phoneNumber: ord.phoneNumber });
    if (ord.status === 'expiring' && (Date.now() - (ord.expiringAt || 0)) > 2 * 60 * 1000) {
      if (ord.balanceRefunded) {
        try { const freshStuck = await getOtpOrder(ordId); await saveOtpOrder(ordId, Object.assign({}, freshStuck.data || ord, { status: 'expired', refunded: true, refundedAt: ord.refundedAt || Date.now() }), freshStuck.sha || null); } catch(e) {}
        return res.json({ ok: true, status: 'expired', refunded: true });
      }
      try {
        const preFlagR = await getOtpOrder(ordId);
        await saveOtpOrder(ordId, Object.assign({}, preFlagR.data || ord, { balanceRefunded: true, _refundingAt: Date.now() }), preFlagR.sha || null);
        await updateBalance(req.user, ord.price);
        const freshStuck = await getOtpOrder(ordId);
        await saveOtpOrder(ordId, Object.assign({}, freshStuck.data || ord, { status: 'expired', refunded: true, refundedAt: Date.now(), balanceRefunded: true }), freshStuck.sha || null);
        return res.json({ ok: true, status: 'expired', refunded: true });
      } catch(rescueErr) { return res.json({ ok: true, status: 'expiring', otp: null }); }
    }
    if (ord.status === 'expiring') return res.json({ ok: true, status: 'expiring', otp: null });
    if (Date.now() > ord.expiresAt && ord.status === 'waiting') {
      try { await saveOtpOrder(ordId, Object.assign({}, ord, { status: 'expiring', expiringAt: Date.now() }), r.sha); }
      catch(lockErr) { const freshR = await getOtpOrder(ordId); const fs = (freshR.data && freshR.data.status) || 'expired'; return res.json({ ok: true, status: fs === 'expiring' ? 'expired' : fs, otp: null }); }
      let refunded = false;
      try {
        const preRefundR = await getOtpOrder(ordId).catch(function(){ return { data: ord, sha: null }; });
        await saveOtpOrder(ordId, Object.assign({}, preRefundR.data || ord, { balanceRefunded: true, _refundingAt: Date.now() }), preRefundR.sha || null).catch(function(){});
        await updateBalance(req.user, ord.price); refunded = true;
      } catch(refErr) { return res.json({ ok: false, message: 'Gagal mengembalikan saldo. Hubungi admin. ID: ' + ordId }); }
      const freshR2 = await getOtpOrder(ordId);
      await saveOtpOrder(ordId, Object.assign({}, freshR2.data || ord, { status: 'expired', refunded, balanceRefunded: true, refundedAt: refunded ? Date.now() : null, expiredAutoAt: Date.now() }), freshR2.sha || null);
      return res.json({ ok: true, status: 'expired', otp: null, refunded });
    }
    let rotpStatus, rotpOtp;
    try {
      const sr = await rotp.get('/api/v1/orders/get_status?order_id=' + ord.rotpOrderId);
      if (sr.success && sr.data) { rotpStatus = sr.data.status; rotpOtp = (sr.data.otp_code && sr.data.otp_code !== '-') ? sr.data.otp_code : null; }
      else { rotpStatus = ord.status; }
    } catch(e) { return res.json({ ok: true, status: ord.status, otp: ord.otp, phoneNumber: ord.phoneNumber }); }
    const finalStatus = (rotpStatus === 'received' || rotpStatus === 'completed') ? 'completed' : rotpStatus;
    if (finalStatus !== ord.status || (rotpOtp && rotpOtp !== ord.otp)) {
      await saveOtpOrder(ordId, Object.assign({}, ord, { status: finalStatus, otp: rotpOtp || ord.otp, updatedAt: Date.now() }), r.sha);
      if (finalStatus === 'completed') broadcastAdmin({ type: 'otp_completed', id: ordId, username: req.user, service: ord.service, country: ord.country, price: ord.price, phone: ord.phoneNumber || '', otp: rotpOtp || ord.otp || '', ts: Date.now() });
    }
    res.json({ ok: true, status: finalStatus, otp: rotpOtp || ord.otp, phoneNumber: ord.phoneNumber });
  } catch(e) { console.error('[otp/status]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/otp/order/:id/cancel', userAuth, async function(req, res) {
  try {
    const ordId = req.params.id;
    if (!isValidOtpId(ordId)) return res.json({ ok: false, message: 'ID tidak valid.' });
    if (!rateLimit('otpcancel:' + ordId, 2, 30 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak permintaan. Tunggu sebentar.' });
    const r = await getOtpOrder(ordId);
    if (!r.data) return res.json({ ok: false, message: 'Order tidak ditemukan.' });
    if (r.data.username !== req.user) return res.status(403).json({ ok: false, message: 'Akses ditolak.' });
    const ord = r.data;
    if (ord.status === 'completed') return res.json({ ok: false, message: 'OTP sudah diterima, tidak bisa dibatalkan.' });
    if (ord.status === 'canceled')  return res.json({ ok: false, message: 'Order sudah dibatalkan.' });
    if (ord.status === 'canceling') return res.json({ ok: false, message: 'Pembatalan sedang diproses, mohon tunggu.' });
    if (ord.status === 'expiring')  return res.json({ ok: false, message: 'Order sedang diproses, mohon tunggu.' });
    if (ord.status === 'expired' && ord.refunded) return res.json({ ok: false, message: 'Order sudah kadaluarsa dan saldo sudah dikembalikan otomatis.' });
    if (ord.refunded) return res.json({ ok: false, message: 'Order ini sudah pernah direfund.' });

    try { await saveOtpOrder(ordId, Object.assign({}, ord, { status: 'canceling', cancelingAt: Date.now(), balanceRefunded: true }), r.sha); }
    catch(lockErr) { return res.json({ ok: false, message: 'Konflik permintaan, coba lagi.' }); }
    try { await rotp.cancelOrder(ord.rotpOrderId); } catch(e) {}
    let newBal;
    try { newBal = await updateBalance(req.user, ord.price); }
    catch(balErr) {

      const fresh = await getOtpOrder(ordId);
      await saveOtpOrder(ordId, Object.assign({}, fresh.data || ord, { status: 'waiting', cancelingAt: null, balanceRefunded: false }), fresh.sha || null).catch(function(){});
      return res.json({ ok: false, message: 'Gagal update saldo. Hubungi admin. ID: ' + ordId });
    }
    const fresh2 = await getOtpOrder(ordId);
    await saveOtpOrder(ordId, Object.assign({}, fresh2.data || ord, { status: 'canceled', cancelledAt: Date.now(), refunded: true, refundedAt: Date.now() }), fresh2.sha || null);
    res.json({ ok: true, balance: newBal });
  } catch(e) { console.error('[otp/cancel]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/otp/orders', userAuth, async function(req, res) {
  try { const orders = await listOtpOrders(req.user); res.json({ ok: true, data: orders.slice(0, 30) }); }
  catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/h2h/products', userAuth, async function(req, res) {
  try {
    if (!rateLimit('h2hprod:' + (req.ip||'x'), 30, 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    const r = await rotp.h2hProducts();
    if (!r.success) return res.json({ ok: false, message: (r.error && r.error.message) || 'Gagal mengambil produk H2H.' });
    res.json({ ok: true, data: r.data });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan: ' + e.message }); }
});

router.get('/api/h2h/rekening', userAuth, async function(req, res) {
  try {
    const r = await rotp.h2hListRekening();
    if (!r.success) return res.json({ ok: false, message: (r.error && r.error.message) || 'Gagal mengambil daftar rekening.' });
    res.json({ ok: true, data: r.data });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan: ' + e.message }); }
});

router.get('/api/h2h/check/rekening', userAuth, async function(req, res) {
  try {
    if (!rateLimit('h2hchkrek:' + req.user, 10, 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    const bank_code      = String(req.query.bank_code      || '').trim();
    const account_number = String(req.query.account_number || '').trim();
    if (!bank_code || !account_number) return res.json({ ok: false, message: 'bank_code dan account_number wajib diisi.' });
    const r = await rotp.h2hCheckRekening(bank_code, account_number);
    if (!r.success) return res.json({ ok: false, message: (r.error && r.error.message) || 'Rekening tidak valid.' });
    res.json({ ok: true, data: r.data });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan: ' + e.message }); }
});

router.get('/api/h2h/username-list', userAuth, async function(req, res) {
  try {
    const r = await rotp.h2hListUsername();
    if (!r.success) return res.json({ ok: false, message: (r.error && r.error.message) || 'Gagal mengambil daftar platform.' });
    res.json({ ok: true, data: r.data });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan: ' + e.message }); }
});

router.get('/api/h2h/check/username', userAuth, async function(req, res) {
  try {
    if (!rateLimit('h2hchkun:' + req.user, 10, 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    const account_code   = String(req.query.account_code   || '').trim();
    const account_number = String(req.query.account_number || '').trim();
    if (!account_code || !account_number) return res.json({ ok: false, message: 'account_code dan account_number wajib diisi.' });
    const r = await rotp.h2hCheckUsername(account_code, account_number);
    if (!r.success) return res.json({ ok: false, message: (r.error && r.error.message) || 'Username tidak valid.' });
    res.json({ ok: true, data: r.data });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan: ' + e.message }); }
});

router.post('/api/h2h/order', userAuth, async function(req, res) {
  try {
    if (!rateLimit('h2horder:' + req.user, 5, 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak order H2H. Tunggu sebentar.' });
    const target = String(req.body.target || '').trim();
    const id     = String(req.body.id     || '').trim();
    if (!target || !id) return res.json({ ok: false, message: 'target dan id (kode produk) wajib diisi.' });
    if (target.length > 50 || id.length > 50) return res.json({ ok: false, message: 'Parameter tidak valid.' });
    const r = await rotp.h2hCreateTransaction(target, id);
    if (!r.success) return res.json({ ok: false, message: (r.error && r.error.message) || 'Gagal membuat transaksi H2H.' });
    res.json({ ok: true, data: r.data });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan: ' + e.message }); }
});

router.get('/api/h2h/order/status', userAuth, async function(req, res) {
  try {
    if (!rateLimit('h2hstatus:' + req.user, 30, 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    const transaksi_id = String(req.query.transaksi_id || '').trim();
    if (!transaksi_id) return res.json({ ok: false, message: 'transaksi_id wajib diisi.' });
    const r = await rotp.h2hTransactionStatus(transaksi_id);
    if (!r.success) return res.json({ ok: false, message: (r.error && r.error.message) || 'Gagal mengambil status transaksi.' });
    res.json({ ok: true, data: r.data });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan: ' + e.message }); }
});

router.post('/api/webhook/rumahotp', async function(req, res) {

  var webhookId = process.env.RUMAHOTP_WEBHOOK_ID || '';
  var incomingId = req.headers['x-requested-id'] || '';
  if (webhookId && incomingId !== webhookId) {
    console.warn('[webhook/rumahotp] x-requested-id tidak cocok:', incomingId);
    return res.status(401).json({ ok: false });
  }

  res.json({ ok: true });

  try {
    var body = req.body || {};

    var rotpOrderId = String(body.order_id || '').trim();
    var status      = String(body.status   || '').trim();
    var otpCode     = (body.otp_code && body.otp_code !== '-') ? String(body.otp_code) : null;
    var otpMsg      = body.otp_msg  || null;

    console.log('[webhook/rumahotp] terima event:', rotpOrderId, status, otpCode ? 'OTP:' + otpCode : '');

    if (!rotpOrderId || !status) return;

    var orders = await listOtpOrders(null);
    var matched = orders.find(function(o) { return o.rotpOrderId === rotpOrderId; });
    if (!matched) {
      console.warn('[webhook/rumahotp] order tidak ditemukan untuk rotpOrderId:', rotpOrderId);
      return;
    }

    var ordId = matched.id;
    var r = await getOtpOrder(ordId);
    if (!r.data) return;
    var ord = r.data;

    if (['completed', 'canceled', 'expired'].includes(ord.status)) return;

    var finalStatus = (status === 'received' || status === 'completed') ? 'completed' : status;
    var newOtp = otpCode || ord.otp || null;

    await saveOtpOrder(ordId, Object.assign({}, ord, {
      status    : finalStatus,
      otp       : newOtp,
      otpMsg    : otpMsg || ord.otpMsg || null,
      updatedAt : Date.now(),
    }), r.sha);

    if (finalStatus === 'completed') {
      broadcastAdmin({ type: 'otp_completed', id: ordId, username: ord.username, service: ord.service, country: ord.country, price: ord.price, phone: ord.phoneNumber || '', otp: newOtp || '', ts: Date.now() });
      console.log('[webhook/rumahotp] OTP completed:', ordId, 'otp:', newOtp);
    }
  } catch(e) {
    console.error('[webhook/rumahotp] error:', e.message);
  }
});

module.exports = router;
