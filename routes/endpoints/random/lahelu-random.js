'use strict';

const { Router } = require('express');
const axios = require('axios');
const { asyncHandler, ValidationError, validate } = require('../../../utils/validation');
const { sendSuccessResponse, sendErrorResponse } = require('../../../config/apikeyConfig');

const router = Router();

async function laheluSearch() {
  try {
    const randomCursor = Math.floor(Math.random() * 5);
    const { data } = await axios.get(
      `https://lahelu.com/api/post/get-recommendations?field=7&cursor=${randomCursor}-0`,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
          Referer: "https://lahelu.com",
          Accept: "application/json, text/plain, */*",
          Connection: "keep-alive",
        },
        timeout: 30000,
      }
    );

    if (!data || !data.postInfos) {
      throw new ValidationError("No posts found", 404);
    }

    return data.postInfos.map(post => ({
      postID: `https://lahelu.com/post/${post.postID}`,
      media: post.media,
      mediaThumbnail: post.mediaThumbnail ? `https://cache.lahelu.com/${post.mediaThumbnail}` : null,
      userUsername: `https://lahelu.com/user/${post.userUsername}`,
      userAvatar: `https://cache.lahelu.com/${post.userAvatar}`,
      createTime: new Date(post.createTime).toISOString(),
      title: post.title || null,
      totalComments: post.totalComments || 0,
    }));
  } catch (error) {
    if (error instanceof ValidationError) throw error;
    throw new ValidationError(error.message || "Failed to get posts from Lahelu", 500);
  }
}

router.get("/api/random/lahelu", asyncHandler(async (req, res) => {
  const data = await laheluSearch();
  sendSuccessResponse(res, {
    total: data.length,
    posts: data
  });
}));

router.post("/api/random/lahelu", asyncHandler(async (req, res) => {
  const data = await laheluSearch();
  sendSuccessResponse(res, {
    total: data.length,
    posts: data
  });
}));

router.metadata = {
  name: "Random Lahelu Posts",
  path: "/api/random/lahelu",
  methods: ['GET', 'POST'],
  category: "RANDOM",
  description: "Get random posts from Lahelu platform (Indonesian meme/content platform). Returns list of posts with media, user info, and timestamps.",
  params: [
  ],
};

module.exports = router;
