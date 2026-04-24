'use strict';

const express = require('express');
const QRCode  = require('qrcode');
const crypto  = require('crypto');
const router  = express.Router();

const C        = require('../lib/config');
const { rateLimit, adminAuth } = require('../lib/auth');
const { dbRead }               = require('../lib/db');
const { getSewabotOrder, saveSewabotOrder, listSewabotOrders, listTrx, newId, _sleep, getEffectiveSettings } = require('../lib/models');
const { pgw, _pgwConfigured }  = require('../lib/payment');
const { broadcastAdmin }       = require('../lib/broadcast');

router.get('/api/sewabot/info', async function(req, res) {
  try { const r = await dbRead('sewabot-config.json'); const cfg = r.data || { prices: { 7: 15000, 14: 25000, 30: 45000 }, description: '' }; res.json({ ok: true, data: cfg }); }
  catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/sewabot/order', async function(req, res) {
  try {
    const ip = req.ip || 'x';
    if (!rateLimit('sbot:' + ip, 5, 10 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request. Coba lagi.' });
    const groupUrl  = String(req.body.groupUrl || '').trim();
    const days      = parseInt(req.body.days, 10) || 30;
    const phone     = String(req.body.phone || '').trim();
    const buyerName = String(req.body.buyerName || '').trim().slice(0, 100);
    if (!groupUrl || groupUrl.length < 5) return res.json({ ok: false, message: 'Link grup tidak boleh kosong.' });
    if (groupUrl.length > 500) return res.json({ ok: false, message: 'Link grup terlalu panjang.' });
    if (days < 1 || days > 365) return res.json({ ok: false, message: 'Durasi tidak valid (1-365 hari).' });
    const cfgR = await dbRead('sewabot-config.json');
    const cfg = cfgR.data || { prices: { 7: 15000, 14: 25000, 30: 45000 } };
    const price = parseInt((cfg.prices || {})[String(days)] || (cfg.prices || {})[days], 10) || 15000;
    const orderId = newId('BOT');
    const sbCancelToken = crypto.randomBytes(16).toString('hex');
    let pakData = null, qrBase64 = null, totalBayar = price, adminFee = 0;
    try {
      pakData    = await pgw.create(orderId, price);
      totalBayar = pakData._totalPayment || pakData.total_payment || price;
      adminFee   = pakData._fee || pakData.fee || 0;
      const qs   = pakData._qrisString || pakData.payment_number || '';
      if (!qs) throw new Error('QRIS string kosong');
      qrBase64   = await QRCode.toDataURL(qs, { errorCorrectionLevel: 'M', margin: 2, scale: 8, color: { dark: '#000000', light: '#ffffff' } });
    } catch(e) {
      if (_pgwConfigured()) return res.json({ ok: false, message: 'Gagal membuat pembayaran. Hubungi admin jika masalah berlanjut.' });
      qrBase64 = await QRCode.toDataURL('DEMO-' + orderId, { margin: 2, scale: 8 });
    }
    const stg = await getEffectiveSettings(); const now = Date.now();
    const order = { id: orderId, type: 'sewabot', groupUrl, days, buyerName, phone: phone ? '62' + String(phone).replace(/^0/, '') : null, price, adminFee, totalBayar, qrBase64, pakData, status: 'PENDING', createdAt: now, expiryAt: now + (stg.expiryMin || C.store.expiry) * 60000, demo: !pakData || !_pgwConfigured(), cancelToken: sbCancelToken, creatorIp: req.ip || 'unknown' };
    await saveSewabotOrder(orderId, order, null);
    broadcastAdmin({ type: 'new_sewabot', id: orderId, groupUrl, days, buyerName, totalBayar, ts: Date.now() });
    res.json({ ok: true, orderId, cancelToken: sbCancelToken });
  } catch(e) { console.error('[sewabot/order]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/sewabot/check', async function(req, res) {
  try {
    const id = req.body.id;
    if (!id || id.length > 60) return res.json({ status: 'NOT_FOUND' });
    if (!rateLimit('sbcheck:' + id, 30, 10 * 60 * 1000)) return res.json({ status: 'PENDING' });
    const r = await getSewabotOrder(id); const order = r.data; const sha = r.sha;
    if (!order) return res.json({ status: 'NOT_FOUND' });
    if (order.status === 'COMPLETED') return res.json({ status: 'COMPLETED', data: { groupUrl: order.groupUrl, days: order.days, buyerName: order.buyerName } });
    if (order.status === 'FAILED' || order.status === 'EXPIRED') return res.json({ status: order.status });
    if (order.status === 'PROCESSING') {
      if (order.processingAt && Date.now() - order.processingAt > 3 * 60 * 1000) await saveSewabotOrder(id, Object.assign({}, order, { status: 'PENDING', processingAt: null }), sha).catch(function(){});
      return res.json({ status: 'PENDING' });
    }
    if (Date.now() > order.expiryAt) { await saveSewabotOrder(id, Object.assign({}, order, { status: 'EXPIRED' }), sha); return res.json({ status: 'EXPIRED' }); }
    if (order.demo) return res.json({ status: 'PENDING' });
    const pakRes    = await pgw.check(id, order.price, order.totalBayar, order.createdAt, order.pakData);
    const trxObj    = pakRes && pakRes.transaction;
    const pakStatus = ((trxObj && trxObj.status) || (pakRes && pakRes.data && pakRes.data.status) || (pakRes && pakRes.status) || '').toLowerCase();
    if (pakStatus === 'completed' || pakStatus === 'paid' || pakStatus === 'success') {
      try { await saveSewabotOrder(id, Object.assign({}, order, { status: 'PROCESSING', processingAt: Date.now() }), sha); }
      catch(lockErr) { return res.json({ status: 'PENDING' }); }
      const freshSb = await getSewabotOrder(id);
      await saveSewabotOrder(id, Object.assign({}, freshSb.data || order, { status: 'COMPLETED', completedAt: Date.now() }), freshSb.sha || null);
      broadcastAdmin({ type: 'sewabot_completed', id, groupUrl: order.groupUrl, days: order.days, buyerName: order.buyerName, totalBayar: order.totalBayar || order.price, ts: Date.now() });
      return res.json({ status: 'COMPLETED', data: { groupUrl: order.groupUrl, days: order.days, buyerName: order.buyerName } });
    }
    if (pakStatus === 'failed' || pakStatus === 'canceled' || pakStatus === 'cancelled') { await saveSewabotOrder(id, Object.assign({}, order, { status: 'FAILED' }), sha); return res.json({ status: 'FAILED' }); }
    return res.json({ status: 'PENDING' });
  } catch(e) { console.error('[sewabot/check]', e.message); return res.json({ status: 'PENDING' }); }
});

router.get('/api/sewabot/:id/qr', async function(req, res) {
  try {
    const id = req.params.id;
    if (!id || id.length > 60) return res.status(404).send('Not found');
    const r = await getSewabotOrder(id);
    if (!r.data || !r.data.qrBase64) return res.status(404).send('No QR');
    if (r.data.status !== 'PENDING') return res.status(410).send('Gone');
    const b64 = r.data.qrBase64.split(',')[1];
    res.set('Content-Type', 'image/png'); res.set('Cache-Control', 'no-store');
    res.send(Buffer.from(b64, 'base64'));
  } catch(e) { res.status(500).send('Error'); }
});

router.get('/api/sewabot/:id', async function(req, res) {
  try {
    const id = req.params.id;
    if (!id || id.length > 60) return res.json({ ok: false, message: 'Tidak ditemukan.' });
    const r = await getSewabotOrder(id);
    if (!r.data) return res.json({ ok: false, message: 'Tidak ditemukan.' });
    const d = Object.assign({}, r.data);

    delete d.qrBase64; delete d.pakData; delete d.cancelToken; delete d.phone; delete d.creatorIp;
    res.json({ ok: true, data: d });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/sewabot/cancel', async function(req, res) {
  try {
    const id = req.body.id; const cancelToken = req.body.cancelToken || '';
    if (!id || id.length > 60) return res.json({ ok: false });
    const r = await getSewabotOrder(id);
    if (!r.data || r.data.status !== 'PENDING') return res.json({ ok: false, message: 'Order tidak bisa dibatalkan.' });
    if (r.data.cancelToken) {
      if (!cancelToken || cancelToken.length !== 32 || cancelToken !== r.data.cancelToken) return res.status(403).json({ ok: false, message: 'Tidak diizinkan membatalkan order ini.' });
    }
    if (!r.data.demo && _pgwConfigured()) await pgw.cancel(id, r.data.price, r.data.totalBayar, r.data.pakData).catch(function(){});
    await saveSewabotOrder(id, Object.assign({}, r.data, { status: 'FAILED', cancelledAt: Date.now() }), r.sha);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/admin/sewabot/orders', adminAuth, async function(req, res) {
  try {
    const orders = await listSewabotOrders();
    const sbIds = new Set(orders.map(function(o){ return o.trxId || o.id; }));
    try {
      const files = await listTrx();
      await Promise.all(files.filter(function(f){ return f.name.endsWith('.json'); }).map(async function(f) {
        try {
          const r = await require('../lib/db').dbRead('transactions/' + f.name);
          if (!r.data) return; const d = r.data;
          if (d.productType !== 'sewabot') return;
          if (d.status !== 'COMPLETED' && d.status !== 'PAID_ERROR') return;
          if (sbIds.has(d.id)) return;
          orders.push({ id: 'BOT-' + d.id, trxId: d.id, groupUrl: d.groupUrl || (d.result && d.result.groupUrl) || '', days: d.variantDays || (d.result && d.result.days) || 30, buyerName: d.buyerName || null, phone: d.phone || null, price: d.unitPrice || 0, adminFee: d.adminFee || 0, totalBayar: d.totalBayar || d.unitPrice || 0, status: 'PROCESSING', createdAt: d.createdAt, completedAt: d.completedAt || null, _reconstructed: true });
        } catch(e) {}
      }));
    } catch(e) {}
    orders.sort(function(a,b){ return (b.createdAt||0)-(a.createdAt||0); });
    res.json({ ok: true, data: orders.slice(0, 200) });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/admin/sewabot/orders/:id/status', adminAuth, async function(req, res) {
  try {
    const id = req.params.id; const status = req.body.status; const note = String(req.body.note || '').slice(0, 500);
    const VALID = ['COMPLETED', 'PENDING', 'FAILED', 'EXPIRED', 'PROCESSING'];
    if (!VALID.includes(status)) return res.json({ ok: false, message: 'Status tidak valid.' });
    if (!id || id.length > 60) return res.json({ ok: false, message: 'ID tidak valid.' });
    const r = await getSewabotOrder(id);
    if (!r.data) return res.json({ ok: false, message: 'Tidak ditemukan.' });
    await saveSewabotOrder(id, Object.assign({}, r.data, { status, adminNote: note, updatedAt: Date.now() }), r.sha);
    require('../lib/models').auditLog('sewabot-status', id + ' -> ' + status, req.adminIp).catch(function(){});
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.get('/api/admin/sewabot/config', adminAuth, async function(req, res) {
  try { const r = await dbRead('sewabot-config.json'); res.json({ ok: true, data: r.data || { prices: { 7: 15000, 14: 25000, 30: 45000 }, description: '' } }); }
  catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});
router.post('/api/admin/sewabot/config', adminAuth, async function(req, res) {
  try {
    const prices = req.body.prices || { 7: 15000, 14: 25000, 30: 45000 };
    const description = String(req.body.description || '').slice(0, 500);
    const enabled = req.body.enabled !== false && req.body.enabled !== 'false';
    const r = await dbRead('sewabot-config.json');
    await require('../lib/db').dbWrite('sewabot-config.json', { prices, description, enabled }, r.sha || null, 'admin: sewabot-config');
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

module.exports = router;
