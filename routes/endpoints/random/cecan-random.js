'use strict';

const { Router } = require('express');
const axios = require('axios');
const { asyncHandler, ValidationError, validate } = require('../../../utils/validation');

const router = Router();

const GIST_URLS = {
  china:     'https://raw.githubusercontent.com/siputzx/Databasee/refs/heads/main/cecan/china.json',
  indonesia: 'https://raw.githubusercontent.com/siputzx/Databasee/refs/heads/main/cecan/indonesia.json',
  japan:     'https://raw.githubusercontent.com/siputzx/Databasee/refs/heads/main/cecan/japan.json',
  korea:     'https://raw.githubusercontent.com/siputzx/Databasee/refs/heads/main/cecan/korea.json',
  thailand:  'https://raw.githubusercontent.com/siputzx/Databasee/refs/heads/main/cecan/thailand.json',
  vietnam:   'https://raw.githubusercontent.com/siputzx/Databasee/refs/heads/main/cecan/vietnam.json',
};

const _cache = {};

async function getImageList(country) {
  if (!GIST_URLS[country]) throw new ValidationError(`Invalid country. Available: ${Object.keys(GIST_URLS).join(', ')}`, 400);
  const c = _cache[country];
  if (c && Date.now() - c.at < 60 * 60 * 1000) return c.urls;
  const { data } = await axios.get(GIST_URLS[country], { timeout: 30000, headers: { 'User-Agent': 'Mozilla/5.0' } });
  if (!Array.isArray(data) || !data.length) throw new ValidationError('No images found', 404);
  _cache[country] = { urls: data, at: Date.now() };
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

function makeHandler(country) {
  return asyncHandler(async (req, res) => {
    const images = await getImageList(country);
    const url = images[Math.floor(Math.random() * images.length)];
    await streamImage(url, res);
  });
}

const COUNTRIES = Object.keys(GIST_URLS);
COUNTRIES.forEach(c => {
  router.get(`/api/random/cecan/${c}`, makeHandler(c));
  router.post(`/api/random/cecan/${c}`, makeHandler(c));
});

router.metadata = COUNTRIES.map(c => ({
  name: `Random Cecan ${c.charAt(0).toUpperCase() + c.slice(1)}`,
  path: `/api/random/cecan/${c}`,
  methods: ['GET', 'POST'],
  category: 'RANDOM',
  description: `Get random ${c} cecan image. Returns image directly.`,
  params: [
  ],
}));

module.exports = router;
