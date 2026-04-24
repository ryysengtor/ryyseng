'use strict';

const express = require('express');
const axios   = require('axios');
const QRCode  = require('qrcode');
const router  = express.Router();

const C         = require('../lib/config');
const { rateLimit }  = require('../lib/auth');
const { listDirCached, _gitTreeCache } = require('../lib/db');
const { getTrx, saveTrx, listTrx, getRsServer, newId, _sleep, getEffectiveSettings } = require('../lib/models');
const { pgw, _pgwConfigured }     = require('../lib/payment');
const { ptH }                     = require('../lib/panel');

router.post('/api/renew/lookup', async function(req, res) {
  try {
    const ip = req.ip || 'x';
    if (!rateLimit('rl:' + ip, 10, 5 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    await new Promise(function(r) { setTimeout(r, 80 + Math.random() * 120); });
    const username = (req.body.username || '').toLowerCase().trim();
    if (!username || username.length < 3 || !/^[a-z0-9_]+$/.test(username)) return res.json({ ok: false, message: 'Format username tidak valid.' });
    const files = await listTrx();
    let found = null;
    for (const f of files.filter(function(f) { return f.name.endsWith('.json'); }).sort(function(a, b) { return b.name.localeCompare(a.name); })) {
      try {
        const r = await getTrx(f.name.replace('.json', ''));
        if (!r.data) continue; const d = r.data;
        if (d.productType !== 'panel') continue;
        if (!d.result || d.result.username !== username) continue;
        if (d.status === 'FAILED' || d._panelDeleted) continue;
        found = d; break;
      } catch(e) {}
    }
    if (!found) {
      try {
        const rsFiles = (await listDirCached('reseller-servers')).filter(function(f){ return f.name.endsWith('.json'); });
        for (const f of rsFiles) {
          try {
            const r = await getRsServer(f.name.replace('.json',''));
            if (r.data && r.data.panelUsername === username && r.data.status !== 'deleted') {
              found = { id: r.data.id, productType: 'panel', variantPlan: r.data.plan || null, variantId: null, status: r.data.status === 'active' ? 'COMPLETED' : 'EXPIRED', _isReseller: true, _rsvId: r.data.id, result: { serverId: r.data.serverId, username: r.data.panelUsername, userId: r.data.userId, ram: r.data.ram, disk: r.data.disk, cpu: r.data.cpu, expiresAt: r.data.expiresAt, domain: r.data.domain } };
              break;
            }
          } catch(e) {}
        }
      } catch(e) {}
    }
    if (!found) return res.json({ ok: false, message: 'Panel tidak ditemukan. Pastikan username sama persis seperti saat beli (tanpa spasi, huruf kecil).' });
    const result = found.result || {};
    var pteroStatus = 'unknown';
    if (C.ptero.domain && C.ptero.apikey && result.serverId) {
      try { await axios.get(C.ptero.domain + '/api/application/servers/' + result.serverId, { headers: ptH() }); pteroStatus = 'active'; }
      catch(e) { if (e.response && e.response.status === 404) pteroStatus = 'deleted'; }
    }
    res.json({ ok: true, username: result.username, plan: found.variantPlan || '1gb', variantId: found.variantId || null, ram: result.ram, disk: result.disk, cpu: result.cpu, expiresAt: result.expiresAt, trxId: found.id, pteroStatus, panelStatus: found.status });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/renew/order', async function(req, res) {
  try {
    const ip = req.ip || 'x';
    if (!rateLimit('ro:' + ip, 5, 10 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    const username = (req.body.username || '').toLowerCase().trim();
    const days     = parseInt(req.body.days, 10) || 30;
    const phone    = req.body.phone || '';
    if (!username || !/^[a-z0-9_]+$/.test(username)) return res.json({ ok: false, message: 'Username tidak valid.' });
    if (days < 1 || days > 365) return res.json({ ok: false, message: 'Durasi tidak valid (1-365 hari).' });
    const files = await listTrx(); let origTrx = null;
    for (const f of files.filter(function(f) { return f.name.endsWith('.json'); }).sort(function(a, b) { return b.name.localeCompare(a.name); })) {
      try {
        const r = await getTrx(f.name.replace('.json', ''));
        if (!r.data) continue; const d = r.data;
        if (d.productType !== 'panel' || !d.result || d.result.username !== username) continue;
        if (d.status === 'FAILED' || d._panelDeleted) continue;
        origTrx = d; break;
      } catch(e) {}
    }
    if (!origTrx) {
      try {
        const rsFiles = (await listDirCached('reseller-servers')).filter(function(f){ return f.name.endsWith('.json'); });
        for (const f of rsFiles) {
          try {
            const r = await getRsServer(f.name.replace('.json',''));
            if (r.data && r.data.panelUsername === username && r.data.status !== 'deleted') {
              origTrx = { id: r.data.id, _rsvId: r.data.id, _isReseller: true, productId: null, productName: 'Panel Reseller', variantId: null, variantName: (r.data.plan || '').toUpperCase(), variantPlan: r.data.plan || null };
              break;
            }
          } catch(e) {}
        }
      } catch(e) {}
    }
    if (!origTrx) return res.json({ ok: false, message: 'Panel tidak ditemukan.' });
    const products = await require('../lib/models').getProducts(); const pp = products.find(function(p) { return p.type === 'panel'; });
    let renewPrice = 10000;
    if (pp) {
      const mv = pp.variants.find(function(v) { return v.plan === (origTrx.variantPlan || '1gb'); }) || (origTrx.variantId && pp.variants.find(function(v) { return v.id === origTrx.variantId; })) || pp.variants[0];
      if (mv) renewPrice = (mv.dayPrices && mv.dayPrices[String(days)]) ? mv.dayPrices[String(days)] : Math.round((mv.salePrice != null && mv.salePrice >= 0 ? mv.salePrice : (mv.price || renewPrice)) * days / 30);
    }
    const orderId = newId('RNW'); let pakData = null, qrBase64 = null, totalBayar = renewPrice, adminFee = 0;
    try {
      pakData    = await pgw.create(orderId, renewPrice);
      totalBayar = pakData._totalPayment || pakData.total_payment || renewPrice;
      adminFee   = pakData._fee || pakData.fee || 0;
      const _renewQs = pakData._qrisString || '';
      if (!_renewQs) throw new Error('QRIS string kosong');
      qrBase64   = await QRCode.toDataURL(_renewQs, { errorCorrectionLevel: 'M', margin: 2, scale: 8, color: { dark: '#000000', light: '#ffffff' } });
    } catch(e) {
      if (_pgwConfigured()) return res.json({ ok: false, message: 'Gagal membuat pembayaran renewal: ' + 'Hubungi admin jika masalah berlanjut.' + '. Hubungi admin.' });
      qrBase64 = await QRCode.toDataURL('DEMO-' + orderId, { margin: 2, scale: 8 });
    }
    const stg = await getEffectiveSettings(); const now = Date.now();
    const trx = { id: orderId, type: 'renewal', productId: origTrx.productId, productName: origTrx.productName, productType: 'panel', variantId: origTrx.variantId, variantName: origTrx.variantName, variantPlan: origTrx.variantPlan, variantDays: days, panelUsername: username, origTrxId: origTrx.id, unitPrice: renewPrice, adminFee, totalBayar, phone: phone ? '62' + String(phone).replace(/^0/, '') : null, qrBase64, pakData, status: 'PENDING', createdAt: now, expiryAt: now + (stg.expiryMin || C.store.expiry) * 60000, demo: !pakData || !_pgwConfigured() };
    await saveTrx(orderId, trx, null);
    res.json({ ok: true, orderId });
  } catch(e) { console.error('[renew/order]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

module.exports = router;
