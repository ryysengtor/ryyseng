'use strict';

const express = require('express');
const crypto  = require('crypto');
const router  = express.Router();

const { rateLimit, adminAuth } = require('../lib/auth');
const { getReviews, saveReviews, getUser, auditLog, _sleep } = require('../lib/models');
const { userAuth }    = require('../lib/user-auth');

const _PROFANITY_LIST = ['anjing','anjg','anying','bangsat','bajingan','brengsek','kontol','memek','ngentot','jancok','jancuk','cuk','asu','monyet','goblok','tolol','idiot','bego','kampret','keparat','setan','iblis','laknat','kadal','babi','kimak','cibai','pukimak','pepek','titit','coli','colmek','ngaceng','bokep','erek','sange','fuck','shit','bitch','asshole','dickhead','cunt','pussy','nigger','nigga','whore','slut','bastard','motherfucker','fucker','wtf','stfu'];
const _BANNED_NAMES = ['kontol','memek','pepek','titit','coli','ngentot','jancok','jancuk','cuk','pukimak','kimak','cibai','ngaceng','bokep','erek','porn','fuck','shit','bitch','cunt','pussy','nigger','nigga','whore','slut'];
function _censorText(text) { var t = text; _PROFANITY_LIST.forEach(function(w) { var re = new RegExp('(?<![a-z])' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![a-z])', 'gi'); t = t.replace(re, function(m) { return '*'.repeat(m.length); }); }); return t; }
function _hasBadName(name) { var l = name.toLowerCase().replace(/[^a-z]/g, ''); return _BANNED_NAMES.some(function(w) { return l.includes(w); }); }
function newRevId() { return 'REV-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex'); }

router.get('/api/reviews', async function(req, res) {
  try {
    if (!rateLimit('rev-read:' + (req.ip||'x'), 30, 60000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    var page = Math.max(1, parseInt(req.query.page, 10) || 1); var star = parseInt(req.query.star, 10) || 0;
    var sort = ['newest','oldest','highest','lowest'].includes(req.query.sort) ? req.query.sort : 'newest'; var limit = 10;
    var r = await getReviews(); var all = Array.isArray(r.data) ? r.data : [];
    var starCounts = { 1:0, 2:0, 3:0, 4:0, 5:0 }; var sumStar = 0;
    all.forEach(function(rv) { if (rv.star >= 1 && rv.star <= 5) { starCounts[rv.star]++; sumStar += rv.star; } });
    var avgRating = all.length > 0 ? (sumStar / all.length).toFixed(1) : '0.0';
    var withPhoto = all.filter(function(rv) { return rv.photoUrl; }).length;
    var filtered = star > 0 ? all.filter(function(rv) { return rv.star === star; }) : all.slice();
    if (req.query.photo === '1') filtered = filtered.filter(function(rv) { return rv.photoUrl; });
    if (sort === 'oldest') filtered.sort(function(a,b) { return (a.createdAt||0)-(b.createdAt||0); });
    else if (sort === 'highest') filtered.sort(function(a,b) { return (b.star||0)-(a.star||0) || (b.createdAt||0)-(a.createdAt||0); });
    else if (sort === 'lowest')  filtered.sort(function(a,b) { return (a.star||0)-(b.star||0) || (b.createdAt||0)-(a.createdAt||0); });
    else filtered.sort(function(a,b) { return (b.createdAt||0)-(a.createdAt||0); });
    var totalFiltered = filtered.length; var paged = filtered.slice((page-1)*limit, page*limit);
    var clean = paged.map(function(rv) { return { id: rv.id, username: rv.username, displayName: rv.displayName, star: rv.star, text: rv.text, photoUrl: rv.photoUrl || null, createdAt: rv.createdAt, helpful: rv.helpful || 0 }; });
    res.json({ ok: true, reviews: clean, total: totalFiltered, totalAll: all.length, page, pages: Math.ceil(totalFiltered / limit), avgRating, starCounts, withPhoto });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/reviews', userAuth, async function(req, res) {
  try {
    if (!rateLimit('rev-post:' + req.user, 3, 60 * 60 * 1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak ulasan. Tunggu sebentar.' });
    var star     = parseInt(req.body.star, 10); var rawName = String(req.body.displayName || '').trim().slice(0, 50);
    var rawText  = String(req.body.text || '').trim().slice(0, 1000); var photoUrl = String(req.body.photoUrl || '').trim().slice(0, 500);
    if (!star || star < 1 || star > 5) return res.json({ ok: false, message: 'Rating bintang tidak valid (1–5).' });
    if (!rawName || rawName.length < 2) return res.json({ ok: false, message: 'Nama pengirim minimal 2 karakter.' });
    if (_hasBadName(rawName)) return res.json({ ok: false, message: 'Nama mengandung kata yang tidak diizinkan. Gunakan nama yang sopan.' });
    if (!rawText || rawText.length < 5) return res.json({ ok: false, message: 'Ulasan minimal 5 karakter.' });
    var cleanText = _censorText(rawText);
    var safePhoto = '';
    if (photoUrl) { if (photoUrl.startsWith('/cdn/') || /^https?:\/\//.test(photoUrl)) { safePhoto = photoUrl; } }
    var ur = await getUser(req.user);
    if (!ur.data) return res.json({ ok: false, message: 'User tidak ditemukan.' });
    if (ur.data.banned) return res.json({ ok: false, message: 'Akun diblokir.' });
    var existing = await getReviews(); var allRevs = Array.isArray(existing.data) ? existing.data : [];
    var recent = allRevs.find(function(rv) { return rv.username === req.user && Date.now() - (rv.createdAt||0) < 24*60*60*1000; });
    if (recent) return res.json({ ok: false, message: 'Kamu sudah memberikan ulasan dalam 24 jam terakhir.' });
    var rev = { id: newRevId(), username: req.user, displayName: rawName, star, text: cleanText, photoUrl: safePhoto || null, createdAt: Date.now(), helpful: 0 };
    for (var _rt = 0; _rt < 3; _rt++) {
      try {
        var fr = await getReviews(); var arr = Array.isArray(fr.data) ? fr.data : [];
        arr.unshift(rev); if (arr.length > 500) arr.length = 500;
        await saveReviews(arr, fr.sha || null); break;
      } catch(e) { if (_rt < 2 && (e.status === 409 || e.status === 422)) { await _sleep(300*(_rt+1)); continue; } throw e; }
    }
    res.json({ ok: true, review: { id: rev.id, displayName: rev.displayName, star: rev.star, text: rev.text, photoUrl: rev.photoUrl, createdAt: rev.createdAt } });
  } catch(e) { console.error('[review/post]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.delete('/api/reviews/:id', adminAuth, async function(req, res) {
  try {
    var id = req.params.id;
    if (!id || !/^REV-\d{13}-[a-f0-9]{8}$/.test(id)) return res.json({ ok: false, message: 'ID tidak valid.' });
    for (var _rt = 0; _rt < 3; _rt++) {
      try {
        var fr = await getReviews(); var arr = Array.isArray(fr.data) ? fr.data : [];
        var idx = arr.findIndex(function(rv) { return rv.id === id; });
        if (idx < 0) return res.json({ ok: false, message: 'Ulasan tidak ditemukan.' });
        arr.splice(idx, 1); await saveReviews(arr, fr.sha || null); break;
      } catch(e) { if (_rt < 2 && (e.status === 409 || e.status === 422)) { await _sleep(300*(_rt+1)); continue; } throw e; }
    }
    auditLog('delete-review', id, req.adminIp).catch(function(){});
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/reviews/:id/helpful', async function(req, res) {
  try {
    var id = req.params.id; var ip = req.ip || 'x';
    if (!rateLimit('helpful:' + ip, 20, 60*60*1000)) return res.status(429).json({ ok: false });
    if (!id || !/^REV-\d{13}-[a-f0-9]{8}$/.test(id)) return res.json({ ok: false });
    for (var _rt = 0; _rt < 3; _rt++) {
      try {
        var fr = await getReviews(); var arr = Array.isArray(fr.data) ? fr.data : [];
        var idx = arr.findIndex(function(rv) { return rv.id === id; });
        if (idx < 0) return res.json({ ok: false });
        arr[idx].helpful = (arr[idx].helpful || 0) + 1;
        await saveReviews(arr, fr.sha || null); return res.json({ ok: true, helpful: arr[idx].helpful });
      } catch(e) { if (_rt < 2 && (e.status === 409 || e.status === 422)) { await _sleep(300*(_rt+1)); continue; } throw e; }
    }
  } catch(e) { res.json({ ok: false }); }
});

router.delete('/api/admin/reviews', adminAuth, async function(req, res) {
  try { var fr = await getReviews(); await saveReviews([], fr.sha || null); auditLog('clear-reviews', 'Reviews dihapus', req.adminIp).catch(function(){}); res.json({ ok: true, message: 'Semua ulasan dihapus.' }); }
  catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

module.exports = router;
