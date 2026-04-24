'use strict';

const { Router } = require('express');
const axios = require('axios');
const cheerio = require('cheerio');

const { asyncHandler, ValidationError, validate } = require('../../../utils/validation');
const { sendSuccessResponse, sendErrorResponse } = require('../../../config/apikeyConfig');

const router = Router();

async function getQuotesAnime() {
  try {
    const page = Math.floor(Math.random() * 184);
    const { data } = await axios.get(`https://otakotaku.com/quote/feed/${page}`, {
      timeout: 30000,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
      },
    });

    const $ = cheerio.load(data);
    const hasil = [];

    $("div.kotodama-list").each(function (l, h) {
      hasil.push({
        link: $(h).find("a").attr("href"),
        gambar: $(h).find("img").attr("data-src"),
        karakter: $(h).find("div.char-name").text().trim(),
        anime: $(h).find("div.anime-title").text().trim(),
        episode: $(h).find("div.meta").text(),
        up_at: $(h).find("small.meta").text(),
        quotes: $(h).find("div.quote").text().trim(),
      });
    });

    if (hasil.length === 0) {
      throw new ValidationError("No quotes found", 404);
    }

    return hasil;
  } catch (error) {
    if (error instanceof ValidationError) throw error;
    throw new ValidationError(error.message || "Failed to get anime quotes", 500);
  }
}

router.get("/api/random/quotes-anime", asyncHandler(async (req, res) => {
  const data = await getQuotesAnime();
  sendSuccessResponse(res, {
    total: data.length,
    quotes: data
  });
}));

router.post("/api/random/quotes-anime", asyncHandler(async (req, res) => {
  const data = await getQuotesAnime();
  sendSuccessResponse(res, {
    total: data.length,
    quotes: data
  });
}));

router.metadata = {
  name: "Random Anime Quotes",
  path: "/api/random/quotes-anime",
  methods: ['GET', 'POST'],
  category: "RANDOM",
  description: "Get random anime quotes with character name, anime title, episode, image, and upload time from otakotaku.com. Returns multiple quotes per request.",
  params: [
  ],
};

module.exports = router;
