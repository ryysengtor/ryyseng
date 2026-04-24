'use strict';

const express = require('express');
const crypto  = require('crypto');
const router  = express.Router();

const { rateLimit }  = require('../lib/auth');
const { getUser, getChatMessages, saveChatMessages, _sleep } = require('../lib/models');
const { userAuth }   = require('../lib/user-auth');

const _PROFANITY_LIST = [
  'anjing','anjg','anying','bangsat','bajingan','brengsek','kontol','memek',
  'ngentot','jancok','jancuk','cuk','asu','monyet','goblok','tolol','idiot',
  'bego','kampret','keparat','setan','iblis','laknat','kadal','babi','kimak',
  'cibai','pukimak','pepek','titit','coli','colmek','ngaceng','bokep','erek',
  'sange','fuck','shit','bitch','asshole','dickhead','cunt','pussy','nigger',
  'nigga','whore','slut','bastard','motherfucker','fucker','wtf','stfu',
];
const _BANNED_NAMES = [
  'kontol','memek','pepek','titit','coli','ngentot','jancok','jancuk','cuk',
  'pukimak','kimak','cibai','ngaceng','bokep','erek','porn','fuck','shit',
  'bitch','cunt','pussy','nigger','nigga','whore','slut',
];
function _censorText(text) {
  var t = text;
  _PROFANITY_LIST.forEach(function(w) {
    var re = new RegExp('(?<![a-z])' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![a-z])', 'gi');
    t = t.replace(re, function(m) { return '*'.repeat(m.length); });
  });
  return t;
}
function _hasBadName(name) {
  var l = name.toLowerCase().replace(/[^a-z]/g, '');
  return _BANNED_NAMES.some(function(w) { return l.includes(w); });
}
function newMsgId() { return 'MSG-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex'); }

router.get('/api/chat', async function(req, res) {
  try {
    if (!rateLimit('chat-read:' + (req.ip||'x'), 120, 60000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    var since = parseInt(req.query.since, 10) || 0;
    var limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
    var r   = await getChatMessages();
    var all = Array.isArray(r.data) ? r.data : [];
    var sorted   = all.slice().reverse();
    var messages = since > 0 ? sorted.filter(function(m) { return (m.createdAt||0) > since; }) : sorted.slice(-limit);
    var clean = messages.map(function(m) { return { id: m.id, username: m.username, displayName: m.displayName || m.username, text: m.text || '', photoUrl: m.photoUrl || null, createdAt: m.createdAt }; });
    res.json({ ok: true, messages: clean, total: all.length });
  } catch(e) { res.json({ ok: false, messages: [], message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.post('/api/chat', userAuth, async function(req, res) {
  try {
    var ip = req.ip || 'x';
    if (!rateLimit('chat-send:' + req.user, 5, 10*1000)) return res.status(429).json({ ok: false, message: 'Terlalu cepat! Tunggu sebentar.' });
    if (!rateLimit('chat-ip:' + ip, 10, 10*1000)) return res.status(429).json({ ok: false, message: 'Terlalu banyak request.' });
    var rawText  = String(req.body.text || '').trim().slice(0, 1000);
    var photoUrl = String(req.body.photoUrl || '').trim().slice(0, 500);
    var rawName  = String(req.body.displayName || req.user).trim().slice(0, 50);
    if (!rawText && !photoUrl) return res.json({ ok: false, message: 'Pesan tidak boleh kosong.' });
    var cleanText = rawText ? _censorText(rawText) : '';
    var safePhoto = '';
    if (photoUrl) {
      if (photoUrl.startsWith('/cdn/') || /^https?:\/\//.test(photoUrl)) {
        safePhoto = photoUrl;
      } else return res.json({ ok: false, message: 'URL foto tidak valid.' });
    }
    var ur = await getUser(req.user);
    if (!ur.data) return res.json({ ok: false, message: 'User tidak ditemukan.' });
    if (ur.data.banned) return res.json({ ok: false, message: 'Akun diblokir.' });
    var msg = { id: newMsgId(), username: req.user, displayName: rawName, text: cleanText, photoUrl: safePhoto || null, createdAt: Date.now() };
    for (var _rt = 0; _rt < 3; _rt++) {
      try {
        var fr = await getChatMessages();
        var arr = Array.isArray(fr.data) ? fr.data : [];
        arr.unshift(msg);
        if (arr.length > 200) arr.length = 200;
        await saveChatMessages(arr, fr.sha || null);
        break;
      } catch(e) {
        if (_rt < 2 && (e.status === 409 || e.status === 422)) { await _sleep(200*(_rt+1)); continue; }
        throw e;
      }
    }
    res.json({ ok: true, message: { id: msg.id, username: msg.username, displayName: msg.displayName, text: msg.text, photoUrl: msg.photoUrl, createdAt: msg.createdAt } });
  } catch(e) { console.error('[chat/send]', e.message); res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

router.delete('/api/chat/:id', userAuth, async function(req, res) {
  try {
    var id = req.params.id;
    if (!id || !/^MSG-\d{13}-[a-f0-9]{8}$/.test(id)) return res.json({ ok: false, message: 'ID tidak valid.' });
    const { verifyToken } = require('../lib/auth');
    var adminTok = req.headers['x-admin-token'];
    var isAdmin  = !!(adminTok && verifyToken(adminTok) && verifyToken(adminTok).role === 'admin');
    for (var _rt = 0; _rt < 3; _rt++) {
      try {
        var fr = await getChatMessages();
        var arr = Array.isArray(fr.data) ? fr.data : [];
        var idx = arr.findIndex(function(m) { return m.id === id; });
        if (idx < 0) return res.json({ ok: false, message: 'Pesan tidak ditemukan.' });
        if (!isAdmin && arr[idx].username !== req.user) return res.status(403).json({ ok: false, message: 'Tidak bisa menghapus pesan orang lain.' });
        arr.splice(idx, 1);
        await saveChatMessages(arr, fr.sha || null);
        break;
      } catch(e) {
        if (_rt < 2 && (e.status === 409 || e.status === 422)) { await _sleep(200*(_rt+1)); continue; }
        throw e;
      }
    }
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, message: 'Terjadi kesalahan, coba lagi.' }); }
});

module.exports = router;
