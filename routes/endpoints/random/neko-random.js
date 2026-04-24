'use strict';

const { Router } = require('express');
const axios = require('axios');
const { asyncHandler, ValidationError, validate } = require('../../../utils/validation');

const router = Router();

async function streamImage(imageUrl, res) {
  const imgRes = await axios.get(imageUrl, {
    responseType: 'arraybuffer',
    timeout: 30000,
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
  });
  const ct = imgRes.headers['content-type'] || 'image/jpeg';
  res.setHeader('Content-Type', ct);
  res.setHeader('Cache-Control', 'no-store');
  res.send(Buffer.from(imgRes.data));
}

async function handler(req, res) {
  const { data } = await axios.get('https://api.waifu.pics/sfw/neko', {
    timeout: 30000,
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
  });
  if (!data || !data.url) throw new ValidationError('No image URL found', 404);
  await streamImage(data.url, res);
}

router.get('/api/random/neko', asyncHandler(handler));
router.post('/api/random/neko', asyncHandler(handler));

router.metadata = {
  name: 'Random Anime Neko Image',
  path: '/api/random/neko',
  methods: ['GET', 'POST'],
  category: 'RANDOM',
  description: 'Get random anime neko (cat girl) image from waifu.pics API. Returns image directly.',
  params: [
  ],
};

module.exports = router;
