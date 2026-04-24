'use strict';

const { Router } = require('express');
const axios = require('axios');
const { asyncHandler, ValidationError, validate } = require('../../../utils/validation');

const router = Router();

const GIST_URL = 'https://gist.githubusercontent.com/siputzx/e985e0566c0529df3a2289fd64047d21/raw/1568d9d26ee25dbe82fb0bdf51b5c88727e3f602/bluearchive.json';
let _cachedUrls = null;
let _cachedAt = 0;

async function getImageList() {
  if (_cachedUrls && Date.now() - _cachedAt < 60 * 60 * 1000) return _cachedUrls;
  const { data } = await axios.get(GIST_URL, { timeout: 30000, headers: { 'User-Agent': 'Mozilla/5.0' } });
  if (!Array.isArray(data) || !data.length) throw new ValidationError('No images found', 404);
  _cachedUrls = data;
  _cachedAt = Date.now();
  return data;
}

async function streamImage(imageUrl, res) {
  const imgRes = await axios.get(imageUrl, {
    responseType: 'arraybuffer', timeout: 30000,
    headers: { 'User-Agent': 'Mozilla/5.0' },
  });
  res.setHeader('Content-Type', imgRes.headers['content-type'] || 'image/jpeg');
  res.setHeader('Cache-Control', 'no-store');
  res.send(Buffer.from(imgRes.data));
}

async function handler(req, res) {
  const images = await getImageList();
  const url = images[Math.floor(Math.random() * images.length)];
  await streamImage(url, res);
}

router.get('/api/random/blue-archive', asyncHandler(handler));
router.post('/api/random/blue-archive', asyncHandler(handler));

router.metadata = {
  name: 'Random Blue Archive Image',
  path: '/api/random/blue-archive',
  methods: ['GET', 'POST'],
  category: 'RANDOM',
  description: 'Get random Blue Archive game image. Returns image directly.',
  params: [
  ],
};

module.exports = router;
