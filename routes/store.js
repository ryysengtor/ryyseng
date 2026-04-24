'use strict';

const express  = require('express');
const QRCode   = require('qrcode');
const crypto   = require('crypto');
const axios    = require('axios');
const router   = express.Router();
const C        = require('../lib/config');
const { rateLimit }  = require('../lib/auth');
const { dbRead, dbWrite, listDirCached } = require('../lib/db');
const {
  getProducts, getEffectiveSettings, getTrx, saveTrx, listTrx,
  getSewabotOrder, saveSewabotOrder, getDeposit,
  decrementStock, popAccount, getVouchers,
  newId, _sleep, idrFormat, maskPhone,
} = require('../lib/models');
const { pgw, _pgwConfigured, PAYMENT_GW } = require('../lib/payment');
const { sanitizeUsername, SPEC }          = require('../lib/panel');
const { broadcastAdmin }                  = require('../lib/broadcast');

var _voucherLocks = new Map();
function _acquireVoucherLock(code) {
  if (_voucherLocks.has(code)) return false;
  _voucherLocks.set(code, Date.now());
  return true;
}
function _releaseVoucherLock(code) { _voucherLocks.delete(code); }

setInterval(function() {
  var now = Date.now();
  for (var k of _voucherLocks.keys()) { if (now - _voucherLocks.get(k) > 30000) _voucherLocks.delete(k); }
}, 5 * 60 * 1000);

function processProductDelivery(trx, id) {
  return require('../lib/delivery').processProductDelivery(trx, id);
}

router.get('/api/store-info', async function(req, res) {
  try {
    const stg = await getEffectiveSettings();
    res.json({ ok: true, name: stg.storeName || C.store.name, cs: stg.wa || C.store.wa, wa: stg.wa || C.store.wa, channel: stg.channelWa || C.store.channel || null, logo: stg.logoUrl || null, appLogo: stg.appLogoUrl || null, color: stg.primaryColor || null, description: stg.description || C.store.description || null, instagram: stg.instagram || C.store.instagram || null, tiktok: stg.tiktok || C.store.tiktok || null, expiry: stg.expiryMin || C.store.expiry || 15 });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/products', async function(req, res) {
  var _done = false;
  var _timeout = setTimeout(function() {
    if (!_done) { _done = true; res.json({ ok: false, message: 'Server sedang lambat, coba lagi sebentar.' }); }
  }, 10000);
  try {
    const [stg, products] = await Promise.all([
      getEffectiveSettings().catch(function(){ return {}; }),
      getProducts().catch(function(){ return []; }),
    ]);
    if (_done) return;
    _done = true; clearTimeout(_timeout);
    const pub = products.map(function(p) {
      return Object.assign({}, p, {
        variants: (p.variants || []).map(function(v) { const vv = Object.assign({}, v); delete vv.fileUrl; return vv; }),
      });
    });
    res.json({ ok: true, data: pub, store: stg.storeName, wa: stg.wa, settings: stg });
  } catch(e) {
    if (!_done) { _done = true; clearTimeout(_timeout); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
  }
});

router.get('/api/categories', async function(req, res) {
  try {

    try {
      const r = await dbRead('categories.json');
      if (r.data && Array.isArray(r.data) && r.data.length > 0) {
        return res.json({ ok: true, data: r.data });
      }
    } catch(e) {  }
    const products = await getProducts();
    const seen = new Set();
    const cats = [];
    products.forEach(function(p) {
      var cat = (p.category || '').trim();
      if (cat && !seen.has(cat.toLowerCase())) {
        seen.add(cat.toLowerCase());
        cats.push({ id: 'cat-' + cat.toLowerCase().replace(/\s+/g,'-'), name: cat });
      }
    });
    res.json({ ok: true, data: cats });
  } catch(e) { res.json({ ok: true, data: [] }); }
});

router.get('/api/panel-plans', async function(req, res) {
  try {
    const { getPanelTemplates } = require('../lib/models');
    const templates = await getPanelTemplates();
    const merged = Object.keys(SPEC).map(function(id) {
      const t = templates.find(function(x){ return x.id === id; });
      return { id, name: (t && t.name) || id.toUpperCase(), ram: t ? t.ram : SPEC[id].ram, disk: t ? t.disk : SPEC[id].disk, cpu: t ? t.cpu : SPEC[id].cpu };
    });
    templates.forEach(function(t) { if (!SPEC[t.id]) merged.push({ id: t.id, name: t.name, ram: t.ram, disk: t.disk, cpu: t.cpu }); });
    res.json({ ok: true, data: merged });
  } catch(e) { res.json({ ok: false, data: [] }); }
});

router.get('/api/ptero/nests', async function(req, res) {
  try {
    const { getPteroNests } = require('../lib/panel');
    const nests = await getPteroNests();
    res.json({ ok: true, data: nests });
  } catch(e) { res.json({ ok: false, message: e.message, data: [] }); }
});

router.get('/api/ptero/nests/:nestId/eggs', async function(req, res) {
  try {
    const { getPteroEggsForNest } = require('../lib/panel');
    const eggs = await getPteroEggsForNest(parseInt(req.params.nestId, 10));
    // Strip sensitive/large fields for public
    const safe = eggs.map(function(e) {
      return { id: e.id, nestId: e.nestId, name: e.name, startup: e.startup, docker_images: e.docker_images, variables: e.variables };
    });
    res.json({ ok: true, data: safe });
  } catch(e) { res.json({ ok: false, message: e.message, data: [] }); }
});

const _captchaStore = new Map();
router.get('/api/captcha', async function(req, res) {
  const ops = ['+', '-', '*'];
  const op  = ops[Math.floor(Math.random() * ops.length)];
  const a   = Math.floor(Math.random() * 15) + 2;
  const b   = Math.floor(Math.random() * 10) + 1;
  let answer;
  if (op === '+') answer = a + b;
  else if (op === '-') answer = a - b;
  else answer = a * b;
  const token = crypto.randomBytes(20).toString('hex');
  const expiresAt = Date.now() + 5 * 60 * 1000;
  const { dbWrite } = require('../lib/db');
  try {
    await dbWrite('captcha:' + token, { answer, expiresAt }, null, 'captcha');
  } catch(e) { _captchaStore.set(token, { answer, expiresAt }); }
  if (_captchaStore.size > 500) {
    const now2 = Date.now();
    for (const [k, v] of _captchaStore) { if (v.expiresAt < now2) _captchaStore.delete(k); }
  }
  res.json({ ok: true, token, question: a + ' ' + op + ' ' + b + ' = ?' });
});

async function verifyCaptcha(token, answer) {
  const { dbRead, dbDelete } = require('../lib/db');
  try {
    const r = await dbRead('captcha:' + token, true);
    if (r && r.data) {
      await dbDelete('captcha:' + token).catch(function(){});
      if (r.data.expiresAt < Date.now()) return false;
      return parseInt(answer, 10) === r.data.answer;
    }
  } catch(e) {}
  const entry = _captchaStore.get(token);
  if (!entry) return false;
  _captchaStore.delete(token);
  if (entry.expiresAt < Date.now()) return false;
  return parseInt(answer, 10) === entry.answer;
}

router.post('/api/order', async function(req, res) {
  try {
    const ip = req.ip || 'unknown';
    if (!rateLimit('order:' + ip, 10, 10 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request. Coba lagi.' });
    const { productId, variantId, phone, panelUsername = '', panelPassword = '', voucherCode = '', captchaToken = '', captchaAnswer = '', groupUrl = '', buyerName = '', panelEggRaw = '' } = req.body;
    var _customFieldVals = {};
    Object.keys(req.body).forEach(function(k) { if (k.startsWith('cf_') && k !== 'cf___proto__' && k !== 'cf_constructor' && k !== 'cf_prototype' && Object.prototype.hasOwnProperty.call(req.body, k)) _customFieldVals[k.slice(3)] = String(req.body[k] || '').trim().slice(0, 500); });
    const stgCap = await getEffectiveSettings();
    if (stgCap.maintenanceMode) return res.json({ ok: false, message: stgCap.maintenanceMsg || 'Sedang dalam maintenance.', maintenance: true });
    if (stgCap.captchaEnabled) {
      if (!await verifyCaptcha(captchaToken, captchaAnswer)) return res.json({ ok: false, message: 'Jawaban captcha salah. Muat ulang dan coba lagi.', captchaFailed: true });
    }
    if (!productId || !variantId || productId.length > 64 || variantId.length > 64) return res.json({ ok: false, message: 'Data tidak lengkap.' });

    if (phone !== undefined && phone !== null && phone !== '') {
      const _phoneClean = String(phone).replace(/\D/g, '');
      if (_phoneClean.length < 8 || _phoneClean.length > 15) return res.json({ ok: false, message: 'Nomor telepon tidak valid. Gunakan 8–15 digit angka.' });
    }
    const products = await getProducts();
    const product  = products.find(function(p) { return p.id === productId; });
    if (!product) return res.json({ ok: false, message: 'Produk tidak ditemukan.' });
    const variant  = product.variants.find(function(v) { return v.id === variantId; });
    if (!variant) return res.json({ ok: false, message: 'Varian tidak ditemukan.' });
    if (variant.stock !== undefined && variant.stock !== null && variant.stock !== -1 && variant.stock <= 0) return res.json({ ok: false, message: 'Stok habis.' });
    const productType = product.type || 'digital';
    if (productType === 'sewabot') {
      const gUrl = String(groupUrl).trim();
      if (!gUrl || gUrl.length < 5) return res.json({ ok: false, message: 'Link grup WhatsApp tidak boleh kosong.' });
    }
    if (productType === 'panel') {
      const uSan = sanitizeUsername(panelUsername);
      if (!uSan || uSan.length < 3) return res.json({ ok: false, message: 'Username panel minimal 3 karakter.' });
      if (!panelPassword || panelPassword.trim().length < 6) return res.json({ ok: false, message: 'Password panel minimal 6 karakter.' });
      const reqDays = parseInt(req.body.panelDays, 10);
      if (reqDays) { const allowed = variant.daysOptions || [variant.days || 30]; if (!allowed.includes(reqDays)) return res.json({ ok: false, message: 'Durasi tidak valid.' }); }
    }
    const orderId   = newId('TRX');
    const reqDays2  = parseInt(req.body.panelDays, 10) || variant.days || 30;
    const unitPrice = (productType === 'panel' && variant.dayPrices && variant.dayPrices[String(reqDays2)])
      ? variant.dayPrices[String(reqDays2)] : (variant.salePrice != null && variant.salePrice >= 0 ? variant.salePrice : variant.price);
    const cancelToken = crypto.randomBytes(16).toString('hex');
    let voucherDiscount = 0, appliedVoucherCode = null;
    if (voucherCode && unitPrice > 0) {
      const _vcCode = String(voucherCode).toUpperCase().trim();

      var _vcLocked = _acquireVoucherLock(_vcCode);
      if (!_vcLocked) {

        await _sleep(350);
        _vcLocked = _acquireVoucherLock(_vcCode);
        if (!_vcLocked) {

          console.warn('[voucher] lock timeout, skip voucher:', _vcCode);
        }
      }
      if (_vcLocked) {
      try {
        const vouchers = await getVouchers();
        const vc = vouchers.find(function(v){ return v.code === _vcCode && v.active !== false; });
        if (vc && !(vc.expiresAt && Date.now() > vc.expiresAt) && !(vc.maxUse > 0 && vc.usedCount >= vc.maxUse) && !(vc.minOrder > 0 && unitPrice < vc.minOrder)) {
          if (!vc.productIds || vc.productIds.length === 0 || vc.productIds.includes(productId)) {
            if (vc.type === 'percent') { voucherDiscount = Math.round(unitPrice * vc.value / 100); if (vc.maxDiscount > 0) voucherDiscount = Math.min(voucherDiscount, vc.maxDiscount); }
            else { voucherDiscount = vc.value; }
            voucherDiscount = Math.min(voucherDiscount, unitPrice);
            appliedVoucherCode = vc.code;
            var _vcIncrOk = false;
            for (var _vci = 0; _vci < 3 && !_vcIncrOk; _vci++) {
              try {
                if (_vci > 0) await _sleep(200 * _vci);
                const vr = await dbRead('vouchers.json', true);
                const varr = Array.isArray(vr.data) ? vr.data : [];
                const vi2 = varr.findIndex(function(x){ return x.code === vc.code; });
                if (vi2 >= 0) {
                  if (varr[vi2].maxUse > 0 && (varr[vi2].usedCount || 0) >= varr[vi2].maxUse) { voucherDiscount = 0; appliedVoucherCode = null; break; }
                  varr[vi2].usedCount = (varr[vi2].usedCount || 0) + 1;
                  await dbWrite('vouchers.json', varr, vr.sha, 'voucher-use:' + vc.code);
                  _vcIncrOk = true;
                }
              } catch(vcErr) { if (_vci < 2 && vcErr.status === 409) continue; console.warn('[voucher] increment gagal:', vcErr.message); }
            }
          }
        }
      } catch(e) { console.warn('[voucher]', e.message); }
      finally { _releaseVoucherLock(_vcCode); }
      }
    }
    const effectivePrice = Math.max(0, unitPrice - voucherDiscount);
    const isFree = (effectivePrice === 0);
    let pakData = null, qrBase64 = null, totalBayar = effectivePrice, adminFee = 0;
    if (!isFree) {
      try {
        pakData    = await pgw.create(orderId, effectivePrice);
        totalBayar = pakData._totalPayment || pakData.total_payment || effectivePrice;
        adminFee   = pakData._fee || pakData.fee || 0;
        const qs       = pakData._qrisString || '';
        const qrImgUrl = pakData._qrImage    || '';
        if (qrImgUrl) {
          try {
            const _imgResp = await axios.get(qrImgUrl, { responseType: 'arraybuffer', timeout: 10000 });
            const _ct = (_imgResp.headers['content-type'] || '').split(';')[0].trim();
            if (_ct.startsWith('image/')) {
              qrBase64 = 'data:' + _ct + ';base64,' + Buffer.from(_imgResp.data).toString('base64');
              console.log('[qr/download] OK image/' + _ct + ' dari URL:', qrImgUrl, '| size:', _imgResp.data.byteLength, 'bytes');
            } else {
              console.warn('[qr/download] URL bukan image (content-type: ' + (_ct||'unknown') + '), fallback ke qr_string. URL:', qrImgUrl);
              if (qs) {
                qrBase64 = await QRCode.toDataURL(qs, { errorCorrectionLevel: 'M', margin: 2, scale: 8, color: { dark: '#000000', light: '#ffffff' } });
              } else {
                throw new Error('URL bukan image dan qr_string kosong. Gateway: ' + PAYMENT_GW);
              }
            }
          } catch (_dlErr) {
            console.warn('[qr/download] gagal download dari URL, fallback ke qr_string:', _dlErr.message);
            if (qs) {
              qrBase64 = await QRCode.toDataURL(qs, { errorCorrectionLevel: 'M', margin: 2, scale: 8, color: { dark: '#000000', light: '#ffffff' } });
            } else {
              throw new Error('Gagal download QR dari URL dan qr_string kosong. Gateway: ' + PAYMENT_GW);
            }
          }
        } else if (qs) {
          qrBase64 = await QRCode.toDataURL(qs, { errorCorrectionLevel: 'M', margin: 2, scale: 8, color: { dark: '#000000', light: '#ffffff' } });
        } else {
          throw new Error('QRIS string kosong dari ' + PAYMENT_GW + '. Periksa konfigurasi gateway.');
        }
      } catch(e) {
        console.error('[pgw/create] error:', e.message);
        // Rollback voucher selalu — baik saat gateway error maupun demo mode
        if (appliedVoucherCode) {
          try {
            const _vRB = await dbRead('vouchers.json', true);
            const _vRBArr = Array.isArray(_vRB.data) ? _vRB.data : [];
            const _vRBi = _vRBArr.findIndex(function(x){ return x.code === appliedVoucherCode; });
            if (_vRBi >= 0 && (_vRBArr[_vRBi].usedCount || 0) > 0) { _vRBArr[_vRBi].usedCount = _vRBArr[_vRBi].usedCount - 1; await dbWrite('vouchers.json', _vRBArr, _vRB.sha, 'voucher-rollback:' + appliedVoucherCode); }
          } catch(vRBErr) {}
        }
        if (_pgwConfigured()) {
          return res.json({ ok: false, message: 'Gagal membuat pembayaran. Hubungi admin.' });
        }
        qrBase64 = await QRCode.toDataURL('DEMO-' + orderId, { margin: 2, scale: 8 });
      }
    }
    const stg = await getEffectiveSettings();
    const now = Date.now();
    const trx = {
      id: orderId, productId, productName: product.name, productType, variantId, variantName: variant.name,
      variantPlan: variant.plan || null, variantDays: reqDays2, variantFile: variant.fileUrl || null,
      panelUsername: productType === 'panel' ? sanitizeUsername(panelUsername) : null,
      panelPassword: productType === 'panel' ? panelPassword.trim() : null,
      panelEgg: (function() {
        if (productType !== 'panel' || !panelEggRaw) return null;
        try { const pe = typeof panelEggRaw === 'string' ? JSON.parse(panelEggRaw) : panelEggRaw;
          if (pe && pe.egg && pe.nest) return { egg: parseInt(pe.egg,10), nest: parseInt(pe.nest,10), docker_image: pe.docker_image || null, startup: pe.startup || null, environment: pe.environment || null };
        } catch(e) {}
        return null;
      })(),
      groupUrl: productType === 'sewabot' ? String(groupUrl).trim().slice(0, 500).replace(/[<>"'&]/g, function(c){ return {'<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','&':'&amp;'}[c]; }) : null,
      buyerName: productType === 'sewabot' ? String(buyerName).trim().slice(0, 100).replace(/[<>"'&]/g, function(c){ return {'<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','&':'&amp;'}[c]; }) : null,
      unitPrice, adminFee, totalBayar,
      phone: phone ? '62' + String(phone).replace(/^0/, '') : null,
      qrBase64, pakData, cancelToken, voucherDiscount, voucherCode: appliedVoucherCode,
      customFields: Object.keys(_customFieldVals).length > 0 ? _customFieldVals : null,
      status: isFree ? 'FREE_PENDING' : 'PENDING',
      createdAt: now,
      expiryAt: now + (stg.expiryMin || C.store.expiry) * 60000,
      demo: !isFree && (!pakData || !_pgwConfigured()),
    };
    if (isFree) {
      try {
        const result = await processProductDelivery(trx, orderId);
        trx.status = 'COMPLETED'; trx.result = result; trx.completedAt = now;
        await saveTrx(orderId, trx, null);
        decrementStock(productId, variantId).catch(function(){});
        broadcastAdmin({ type: 'trx_completed', id: orderId, productName: product.name, variantName: variant.name, totalBayar: 0, productType, phone: trx.phone || null, free: true, ts: now });
        return res.json({ ok: true, orderId, free: true });
      } catch(freeErr) {
        await saveTrx(orderId, Object.assign({}, trx, { status: 'FAILED', error: freeErr.message }), null);
        return res.json({ ok: false, message: freeErr.message });
      }
    }
    await saveTrx(orderId, trx, null);
    broadcastAdmin({ type: 'new_order', id: orderId, productName: product.name, variantName: variant.name, totalBayar, productType, ts: now });
    console.log('[order]', orderId, '|', product.name, '|', variant.name, '| Rp' + totalBayar);

    // ── Event-driven: mulai background watcher per-TRX ───────────────────────
    // Memastikan order diproses/expire meski user tutup browser (tanpa cron global)
    require('../lib/event-trigger').triggerTrxWatch(orderId);

    res.json({ ok: true, orderId });
  } catch(e) { console.error('[order]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/check', async function(req, res) {
  try {
    const id  = req.body.id;
    if (!require('../lib/models').isValidId(id)) return res.json({ status: 'NOT_FOUND' });
    if (!rateLimit('chk:' + id, 60, 10 * 60 * 1000)) return res.json({ status: 'PENDING' });
    const r   = await getTrx(id);
    if (!r.data) return res.json({ status: 'NOT_FOUND' });
    const trx = r.data; const sha = r.sha;
    if (trx.status === 'COMPLETED' || trx.status === 'PAID_ERROR') return res.json({ status: 'COMPLETED', result: trx.result || null });
    if (trx.status === 'FAILED' || trx.status === 'EXPIRED') return res.json({ status: trx.status });
    if (trx.status === 'PROCESSING') {
      if (trx.processingAt && Date.now() - trx.processingAt > 3 * 60 * 1000) {
        await saveTrx(id, Object.assign({}, trx, { status: 'PENDING', processingAt: null }), sha).catch(function(){});
      }
      return res.json({ status: 'PENDING' });
    }
    if (Date.now() > trx.expiryAt + 2 * 60 * 1000) { await saveTrx(id, Object.assign({}, trx, { status: 'EXPIRED' }), sha); return res.json({ status: 'EXPIRED' }); }
    if (trx.demo) return res.json({ status: 'PENDING' });
    const pakRes    = await pgw.check(id, trx.unitPrice, trx.totalBayar, trx.createdAt, trx.pakData);
    const trxObj    = (pakRes && pakRes.transaction) || (pakRes && pakRes.data) || pakRes;
    const pakStatus = ((pakRes && pakRes.transaction && pakRes.transaction.status) || (pakRes && pakRes.data && pakRes.data.status) || (pakRes && pakRes.status) || (trxObj && trxObj.status) || (trxObj && trxObj.payment_status) || '').toLowerCase();
    console.log('[check]', id, '| pak_status:', pakStatus);
    if (pakStatus === 'completed' || pakStatus === 'paid' || pakStatus === 'success') {
      try { await saveTrx(id, Object.assign({}, trx, { status: 'PROCESSING', processingAt: Date.now() }), sha); }
      catch(lockErr) { return res.json({ status: 'PENDING' }); }
      try {
        const result = await processProductDelivery(trx, id);
        const freshR = await getTrx(id);
        await saveTrx(id, Object.assign({}, freshR.data || trx, { status: 'COMPLETED', result, completedAt: Date.now() }), freshR.sha || null);
        decrementStock(trx.productId, trx.variantId).catch(function(){});
        broadcastAdmin({ type: 'trx_completed', id, productName: trx.productName, variantName: trx.variantName, totalBayar: trx.totalBayar || trx.unitPrice, productType: trx.productType, phone: trx.phone || null, ts: Date.now() });
        return res.json({ status: 'COMPLETED', result });
      } catch(procErr) {
        const errResult = { type: 'error', message: 'Pembayaran diterima tapi proses gagal. Hubungi admin. ID: ' + id };
        const freshR2 = await getTrx(id);
        await saveTrx(id, Object.assign({}, freshR2.data || trx, { status: 'PAID_ERROR', error: procErr.message, result: errResult }), freshR2.sha || null);
        return res.json({ status: 'COMPLETED', result: errResult });
      }
    }
    if (pakStatus === 'failed' || pakStatus === 'canceled' || pakStatus === 'cancelled') { await saveTrx(id, Object.assign({}, trx, { status: 'FAILED' }), sha); return res.json({ status: 'FAILED' }); }
    return res.json({ status: 'PENDING' });
  } catch(e) { console.error('[check]', e.message); return res.json({ status: 'PENDING' }); }
});

router.post('/api/cancel', async function(req, res) {
  try {
    const id = req.body.id; const cancelToken = req.body.cancelToken || '';
    if (!require('../lib/models').isValidId(id)) return res.json({ ok: false });
    if (!rateLimit('cancel:' + (req.ip || 'x'), 5, 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu cepat.' });
    const r = await getTrx(id);
    if (!r.data) return res.json({ ok: false });
    if (r.data.status !== 'PENDING') return res.json({ ok: false, message: 'Order tidak bisa dibatalkan.' });
    if (r.data.cancelToken) {
      if (!cancelToken || cancelToken.length !== 32 || cancelToken !== r.data.cancelToken) return res.status(403).json({ ok: false, message: 'Tidak diizinkan membatalkan order ini.' });
    }
    if (!r.data.demo && _pgwConfigured()) await pgw.cancel(id, r.data.unitPrice, r.data.totalBayar, r.data.pakData);
    await saveTrx(id, Object.assign({}, r.data, { status: 'FAILED', cancelledAt: Date.now() }), r.sha);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

function _sanitizeHistoryItem(d) {
  const safe = { id: d.id, status: d.status, productName: d.productName || '—', variantName: d.variantName || '—', totalBayar: d.totalBayar || d.unitPrice || 0, createdAt: d.createdAt, phone: d.phone ? d.phone.slice(0,-4)+'****' : null, productType: d.productType || 'digital', customFields: d.customFields || null };
  if ((d.status === 'COMPLETED' || d.status === 'PAID_ERROR') && d.result) {
    const r = d.result;
    if (r.type === 'panel') { safe.result = { type:'panel', domain: r.domain, username: r.username, password: r.password, expiresAt: r.expiresAt, plan: r.plan, ram: r.ram, disk: r.disk, cpu: r.cpu }; }
    else if (r.type === 'content') {
      var ct = String(r.contentText || ''); var parsed = null;
      if (ct.includes('|') || ct.includes(':')) { var sep = ct.includes('|') ? '|' : ':'; var parts = ct.split(sep).map(function(s){ return s.trim(); }); if (parts.length === 2 && parts[0] && parts[1]) parsed = { email: parts[0], password: parts[1] }; else if (parts.length >= 2) parsed = { raw: ct, lines: parts }; }
      else if (ct.includes('\n')) { var lines = ct.split('\n').map(function(l){ return l.trim(); }).filter(Boolean); if (lines.length >= 2) parsed = { lines }; }
      safe.result = { type:'content', contentType: r.contentType, contentUrl: r.contentUrl, contentText: ct, title: r.title || d.variantName, parsedAccount: parsed };
    } else if (r.type === 'renewal') { safe.result = { type:'renewal', domain: r.domain, username: r.username, expiresAt: r.expiresAt, addedDays: r.addedDays }; }
    else if (r.type === 'sewabot')  { safe.result = { type:'sewabot', groupUrl: r.groupUrl, days: r.days }; }
    else if (r.type === 'error')    { safe.result = { type:'error', message: r.message }; }
  }
  return safe;
}

router.post('/api/history', async function(req, res) {
  try {
    const ip = req.ip || 'x';
    if (!rateLimit('hist:' + ip, 8, 60000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak permintaan.' });
    const query = String(req.body.query || '').trim();
    if (!query || query.length < 4) return res.json({ ok: false, message: 'Masukkan nomor HP atau ID transaksi.' });
    var _normalized = query.replace(/^([A-Za-z]+)-/, function(_, p){ return p.toUpperCase() + '-'; }).replace(/-([0-9A-Fa-f]+)$/, function(_, h){ return '-' + h.toLowerCase(); });
    var _isTrxId = /^(TRX|RNW|BOT)-\d{13}-[a-f0-9]{8}$/i.test(query);
    if (_isTrxId) {
      if (_normalized.startsWith('TRX-') || _normalized.startsWith('RNW-')) { try { const r = await getTrx(_normalized); if (r.data) return res.json({ ok: true, data: [_sanitizeHistoryItem(r.data)] }); } catch(e) {} }
      if (_normalized.startsWith('BOT-')) { try { const sb = await getSewabotOrder(_normalized); if (sb.data) return res.json({ ok: true, data: [_sanitizeHistoryItem(Object.assign({ productName: 'Sewa Bot', variantName: sb.data.days + ' Hari', productType: 'sewabot' }, sb.data))] }); } catch(e) {} }
      try { const r = await getTrx(_normalized); if (r.data) return res.json({ ok: true, data: [_sanitizeHistoryItem(r.data)] }); } catch(e) {}
      return res.json({ ok: false, message: 'ID transaksi tidak ditemukan.' });
    }
    const files = await listTrx();
    const phone = query.replace(/[^0-9]/g, '');
    const matches = [];
    await Promise.all(files.filter(function(f){ return f.name.endsWith('.json'); }).map(async function(f) {
      try { const r = await dbRead('transactions/' + f.name); if (!r.data) return; const d = r.data; const dp = (d.phone || '').replace(/[^0-9]/g, ''); if (dp && dp.endsWith(phone.slice(-9))) matches.push(_sanitizeHistoryItem(d)); } catch(e) {}
    }));
    if (/^[a-z0-9_]{3,20}$/.test(query.toLowerCase())) {
      try {
        const depListR = await listDirCached('deposits');
        const depFiles = Array.isArray(depListR) ? depListR.filter(function(f){ return f.name.endsWith('.json'); }) : [];
        await Promise.all(depFiles.map(async function(f) {
          try { const d = await getDeposit(f.name.replace('.json', '')); if (d.data && d.data.username === query.toLowerCase()) matches.push({ type: 'deposit', id: d.data.id, amount: d.data.amount, totalBayarDeposit: d.data.totalBayarDeposit || d.data.amount, adminFeeDeposit: d.data.adminFeeDeposit || 0, status: d.data.status, createdAt: d.data.createdAt }); } catch(e) {}
        }));
      } catch(e) {}
    }
    if (matches.length === 0) return res.json({ ok: false, message: 'Tidak ada order ditemukan.' });
    matches.sort(function(a, b){ return (b.createdAt||0) - (a.createdAt||0); });
    res.json({ ok: true, data: matches.slice(0, 20) });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/trx/:id', async function(req, res) {
  try {
    const id = req.params.id;
    if (!require('../lib/models').isValidId(id)) return res.json({ ok: false, message: 'Transaksi tidak ditemukan.' });
    const r = await getTrx(id);
    if (!r.data) return res.json({ ok: false, message: 'Transaksi tidak ditemukan.' });
    const d = Object.assign({}, r.data);
    d.qrAvailable = !!(r.data.qrBase64 && r.data.status === 'PENDING');
    d.isDemo = !!(r.data.demo);
    // Sertakan qrDataUrl langsung di response kalau sudah berupa data: URL (sudah di-download/generate)
    const _raw = r.data.qrBase64 || '';
    if (_raw.startsWith('data:') && r.data.status === 'PENDING') {
      d.qrDataUrl = _raw;
    }
    delete d.qrBase64; delete d.pakData; delete d.panelPassword; delete d.variantFile;
    res.json({ ok: true, data: d });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/trx/:id/qr', async function(req, res) {
  try {
    const id = req.params.id;
    if (!require('../lib/models').isValidId(id)) return res.status(404).send('Not found');
    const r = await getTrx(id);
    if (!r.data) return res.status(404).send('Not found');
    if (r.data.status === 'COMPLETED' || r.data.status === 'PAID_ERROR') return res.status(410).json({ gone: true, reason: 'paid', message: 'Pembayaran sudah diterima' });
    if (r.data.status === 'FAILED' || r.data.status === 'EXPIRED') return res.status(410).json({ gone: true, reason: r.data.status.toLowerCase(), message: 'Transaksi ' + r.data.status.toLowerCase() });
    if (r.data.status !== 'PENDING') return res.status(410).json({ gone: true, reason: 'status', message: 'Status: ' + r.data.status });
    if (!r.data.qrBase64) return res.status(503).json({ error: 'QR belum tersedia, coba lagi.' });
    const raw = r.data.qrBase64;
    if (raw.startsWith('http://') || raw.startsWith('https://')) {
      try {
        const imgResp = await axios.get(raw, { responseType: 'arraybuffer', timeout: 10000 });
        const ct = imgResp.headers['content-type'] || 'image/png';
        res.set('Content-Type', ct);
        res.set('Cache-Control', 'no-store');
        return res.send(Buffer.from(imgResp.data));
      } catch (proxyErr) {
        console.error('[qr/proxy] gagal fetch gambar QR:', proxyErr.message);
        return res.redirect(raw);
      }
    }

    const b64 = raw.includes(',') ? raw.split(',')[1] : raw;
    if (!b64) return res.status(503).send('QR data invalid');
    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'no-store');
    res.send(Buffer.from(b64, 'base64'));

  } catch(e) { res.status(500).send('Error'); }
});

router.get('/api/trx/:id/stream', async function(req, res) {
  const id = req.params.id;
  if (!require('../lib/models').isValidId(id)) { res.status(400).end(); return; }
  if (!rateLimit('sse:' + id, 5, 60 * 1000)) { res.status(429).end(); return; }
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-store', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.flushHeaders();
  function send(data) { if (!res.writableEnded) { res.write('data: ' + JSON.stringify(data) + '\n\n'); if (typeof res.flush === 'function') res.flush(); } }
  send({ type: 'connected' });
  // Vercel Hobby: limit 10s — gunakan 7s agar aman sebelum Vercel kill koneksi.
  // Client sudah punya auto-reconnect, jadi payment check tetap jalan tiap ~11 detik.
  var IS_VERCEL = !!process.env.VERCEL;
  var MAX_DURATION = IS_VERCEL ? 7000 : 55000;
  var closed = false; var startedAt = Date.now(); var pgwCheckCount = 1;
  req.on('close', function() { closed = true; clearInterval(iv); });
  var iv = setInterval(async function() {
    if (closed) { clearInterval(iv); return; }
    if (Date.now() - startedAt > MAX_DURATION) { send({ type: 'reconnect' }); clearInterval(iv); res.end(); return; }
    try {
      const r = await getTrx(id);
      if (!r.data) { send({ type: 'status', status: 'NOT_FOUND' }); clearInterval(iv); res.end(); return; }
      const trx = r.data; const sha = r.sha;
      if (trx.status === 'COMPLETED' || trx.status === 'PAID_ERROR') { send({ type: 'status', status: 'COMPLETED', result: trx.result || null }); clearInterval(iv); res.end(); return; }
      if (trx.status === 'FAILED' || trx.status === 'EXPIRED') { send({ type: 'status', status: trx.status }); clearInterval(iv); res.end(); return; }
      if (Date.now() > trx.expiryAt + 2 * 60 * 1000) { send({ type: 'status', status: 'EXPIRED' }); clearInterval(iv); res.end(); return; }
      if (trx.status === 'PROCESSING') { send({ type: 'ping', status: 'PENDING' }); return; }
      // ── Cek payment gateway langsung di stream agar pembayaran terdeteksi real-time
      // (tidak perlu tunggu cron). Dilakukan setiap 2 tick (~8 detik) agar tidak overload.
      if (!trx.demo && _pgwConfigured()) {
        pgwCheckCount++;
        if (pgwCheckCount % 2 === 0) {
          try {
            const pakRes    = await pgw.check(id, trx.unitPrice, trx.totalBayar, trx.createdAt, trx.pakData);
            const trxObj    = (pakRes && pakRes.transaction) || (pakRes && pakRes.data) || pakRes;
            const pakStatus = ((pakRes && pakRes.transaction && pakRes.transaction.status) || (pakRes && pakRes.data && pakRes.data.status) || (pakRes && pakRes.status) || (trxObj && trxObj.status) || (trxObj && trxObj.payment_status) || '').toLowerCase();
            if (pakStatus === 'completed' || pakStatus === 'paid' || pakStatus === 'success') {
              try { await saveTrx(id, Object.assign({}, trx, { status: 'PROCESSING', processingAt: Date.now() }), sha); } catch(lkErr) { send({ type: 'ping', status: 'PENDING' }); return; }
              try {
                const result = await processProductDelivery(trx, id);
                const freshR = await getTrx(id);
                await saveTrx(id, Object.assign({}, freshR.data || trx, { status: 'COMPLETED', result, completedAt: Date.now() }), freshR.sha || null);
                decrementStock(trx.productId, trx.variantId).catch(function(){});
                broadcastAdmin({ type: 'trx_completed', id, productName: trx.productName, variantName: trx.variantName, totalBayar: trx.totalBayar || trx.unitPrice, productType: trx.productType, phone: trx.phone || null, ts: Date.now() });
                send({ type: 'status', status: 'COMPLETED', result }); clearInterval(iv); res.end(); return;
              } catch(procErr) {
                const errResult = { type: 'error', message: 'Pembayaran diterima tapi proses gagal. Hubungi admin. ID: ' + id };
                const freshR2 = await getTrx(id);
                await saveTrx(id, Object.assign({}, freshR2.data || trx, { status: 'PAID_ERROR', error: procErr.message, result: errResult }), freshR2.sha || null);
                send({ type: 'status', status: 'COMPLETED', result: errResult }); clearInterval(iv); res.end(); return;
              }
            } else if (pakStatus === 'failed' || pakStatus === 'canceled' || pakStatus === 'cancelled') {
              await saveTrx(id, Object.assign({}, trx, { status: 'FAILED' }), sha).catch(function(){});
              send({ type: 'status', status: 'FAILED' }); clearInterval(iv); res.end(); return;
            }
          } catch(pgwErr) { /* Gateway error sementara — lanjut polling */ }
        }
      }
      send({ type: 'ping', status: trx.status });
    } catch(e) {}
  }, 4000);
});

router.post('/api/voucher', async function(req, res, next) { req.url = '/api/voucher/validate'; next('route'); });
router.post('/api/voucher/validate', async function(req, res) {
  try {
    if (!rateLimit('vcval:' + (req.ip||'x'), 10, 60000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak percobaan.' });
    const { code, productId, amount } = req.body;
    if (!code) return res.json({ ok: false, message: 'Kode voucher kosong.' });
    const vouchers = await getVouchers();
    const v = vouchers.find(function(v){ return v.code === String(code).toUpperCase().trim() && v.active !== false; });
    if (!v) return res.json({ ok: false, message: 'Kode voucher tidak valid.' });
    if (v.expiresAt && Date.now() > v.expiresAt) return res.json({ ok: false, message: 'Voucher sudah kadaluarsa.' });
    if (v.maxUse > 0 && v.usedCount >= v.maxUse) return res.json({ ok: false, message: 'Kuota voucher habis.' });
    if (v.minOrder > 0 && (parseInt(amount, 10)||0) < v.minOrder) return res.json({ ok: false, message: 'Minimum order ' + idrFormat(v.minOrder) });
    if (v.productIds && v.productIds.length > 0 && productId && !v.productIds.includes(productId)) return res.json({ ok: false, message: 'Voucher tidak berlaku untuk produk ini.' });
    let discount = 0; const base = parseInt(amount, 10) || 0;
    if (v.type === 'percent') { discount = Math.round(base * v.value / 100); if (v.maxDiscount > 0) discount = Math.min(discount, v.maxDiscount); }
    else { discount = v.value; }
    discount = Math.min(discount, base);
    res.json({ ok: true, discount, finalAmount: base - discount, code: v.code, desc: v.desc, type: v.type, value: v.value });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

const { _feedBuf, formatFeedEvent, broadcastFeed } = require('../lib/broadcast');
router.get('/api/feed', async function(req, res) {
  if (!rateLimit('feed:' + (req.ip||'x'), 60, 60000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request. Coba lagi.' });
  var typeFilter = req.query.type || 'all'; var limit = Math.min(parseInt(req.query.limit, 10) || 20, 50);
  var source = _feedBuf.slice(); var fromCache = false;
  if (source.length === 0) { try { const r = await dbRead('feed-cache.json'); if (Array.isArray(r.data) && r.data.length > 0) { source = r.data; fromCache = true; } } catch(e) {} }
  var data = source.filter(function(e) { return typeFilter === 'all' || e.type === typeFilter; }).slice(0, limit);
  if (!fromCache) data = data.map(formatFeedEvent);
  res.json({ ok: true, count: data.length, data });
});
router.get('/api/feed/stream', function(req, res) {
  if (!rateLimit('feedsse:' + (req.ip||'x'), 10, 60000)) { res.status(429).end(); return; }
  res.setHeader('Content-Type', 'text/event-stream'); res.setHeader('Cache-Control', 'no-cache'); res.setHeader('Connection', 'keep-alive'); res.setHeader('X-Accel-Buffering', 'no'); res.setHeader('Access-Control-Allow-Origin', '*'); res.flushHeaders();
  function _feedWrite(data) { if (!res.writableEnded) { try { res.write('data: ' + JSON.stringify(data) + '\n\n'); if (typeof res.flush === 'function') res.flush(); return true; } catch(e) { return false; } } return false; }
  _feedBuf.slice(0, 10).reverse().forEach(function(e) { _feedWrite(formatFeedEvent(e)); });
  _feedWrite({ type: 'connected', ts: Date.now() });
  const { _feedClients } = require('../lib/broadcast');
  _feedClients.add(res);
  var IS_VERCEL = !!process.env.VERCEL;
  var MAX_DURATION = IS_VERCEL ? 8000 : 55000;
  var startedAt = Date.now();
  var ping = setInterval(function() {
    if (Date.now() - startedAt > MAX_DURATION) { _feedWrite({ type: 'reconnect' }); clearInterval(ping); _feedClients.delete(res); res.end(); return; }
    if (!_feedWrite({ type: 'ping' })) { clearInterval(ping); _feedClients.delete(res); }
  }, 25000);
  req.on('close', function() { clearInterval(ping); _feedClients.delete(res); });
});

var _imgProxyCache = new Map();
var _imgProxyCacheLastClean = Date.now();
const IMG_PROXY_TTL = 30 * 60 * 1000;
router.get('/api/img-proxy', async function(req, res) {
  var url = req.query.url;
  if (!url || typeof url !== 'string' || url.length > 2048) return res.status(400).end();
  if (!/^https?:\/\/.{4,}/.test(url)) return res.status(400).end();
  try {
    var _pUrl = new URL(url); var _host = _pUrl.hostname.toLowerCase();
    var _BLOCKED_HOSTS = /^(localhost|127\.|0\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|::1|fc00:|fe80:)/;
    if (_BLOCKED_HOSTS.test(_host) || _host === '0.0.0.0' || _host === '[::1]') { console.warn('[img-proxy] SSRF blocked:', url); return res.status(400).end(); }
    var _port = _pUrl.port ? parseInt(_pUrl.port, 10) : (_pUrl.protocol === 'https:' ? 443 : 80);
    if (![80, 443].includes(_port)) return res.status(400).end();
  } catch(urlErr) { return res.status(400).end(); }
  if (!rateLimit('imgp:' + (req.ip||'x'), 120, 60 * 1000)) return res.status(429).end();

  var _now = Date.now();
  if (_now - _imgProxyCacheLastClean > 10 * 60 * 1000) {
    _imgProxyCacheLastClean = _now;
    _imgProxyCache.forEach(function(v, k){ if (_now - v.ts > IMG_PROXY_TTL) _imgProxyCache.delete(k); });
  }
  var cached = _imgProxyCache.get(url);
  if (cached && Date.now() - cached.ts < IMG_PROXY_TTL) {
    res.set('Content-Type', cached.ct);
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'public, max-age=1800');
    return res.send(cached.buf);
  }
  try {
    var r = await axios.get(url, { responseType: 'arraybuffer', timeout: 8000, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ImageProxy/1.0)' }, maxContentLength: 2 * 1024 * 1024 });
    var ct = (r.headers['content-type'] || 'image/png').split(';')[0].trim();
    if (!ct.startsWith('image/')) ct = 'image/png';
    var buf = Buffer.from(r.data);
    _imgProxyCache.set(url, { buf, ct, ts: Date.now() });
    if (_imgProxyCache.size > 200) { var oldest = null; _imgProxyCache.forEach(function(v, k){ if (!oldest || v.ts < _imgProxyCache.get(oldest).ts) oldest = k; }); if (oldest) _imgProxyCache.delete(oldest); }
    res.set('Content-Type', ct);
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'public, max-age=1800');
    res.send(buf);
  } catch(e) { console.warn('[img-proxy] gagal:', url, e.message); res.status(502).end(); }
});
module.exports = router;
