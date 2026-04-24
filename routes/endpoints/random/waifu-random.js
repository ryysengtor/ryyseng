'use strict';

const { Router } = require('express');
const axios = require('axios');
const { asyncHandler, ValidationError, validate } = require('../../../utils/validation');
const { sendErrorResponse } = require('../../../config/apikeyConfig');

const router = Router();

async function getRandomWaifuImage() {
  const { data } = await axios.get('https://api.waifu.pics/sfw/waifu', {
    timeout: 30000,
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
  });
  if (!data || !data.url) throw new ValidationError('No image URL found', 404);
  return data.url;
}

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

router.get('/api/random/waifu', asyncHandler(async (req, res) => {
  const url = await getRandomWaifuImage();
  await streamImage(url, res);
}));

router.post('/api/random/waifu', asyncHandler(async (req, res) => {
  const url = await getRandomWaifuImage();
  await streamImage(url, res);
}));

router.metadata = {
  name: 'Random Waifu Image',
  path: '/api/random/waifu',
  methods: ['GET', 'POST'],
  category: 'RANDOM',
  description: 'Get random anime waifu image from waifu.pics API. Returns image directly.',
  params: [
  ],
};

module.exports = router;
