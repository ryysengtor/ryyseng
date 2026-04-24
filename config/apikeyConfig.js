'use strict';

const { rateLimit } = require('../lib/auth');

const RATE_LIMIT_MAX    = parseInt(process.env.FREE_API_RATE_LIMIT  || '15', 10);
const RATE_LIMIT_WINDOW = parseInt(process.env.FREE_API_RATE_WINDOW || '60000', 10);

const CHANNEL = 'https://whatsapp.com/channel/0029Vb8BOPf4o7qDPYmbkc1p';

function rateLimitMiddleware(req, res, next) {
  const ip  = req.ip || req.socket?.remoteAddress || 'unknown';
  const key = 'free_api:' + ip;

  if (!rateLimit(key, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW)) {
    return res
      .status(429)
      .type('application/json')
      .send(JSON.stringify({
        success : false,
        creator : 'ryysengtor',
        error   : 'Too many requests. Tunggu sebentar dan coba lagi.',
        channel : CHANNEL,
      }, null, 2));
  }

  next();
}

function sendSuccessResponse(res, results) {
  const payload = {
    success : true,
    creator : 'ryysengtor',
    results,
    channel : CHANNEL,
  };
  res
    .status(200)
    .type('application/json')
    .send(JSON.stringify(payload, null, 2));
}

function sendErrorResponse(res, message, status = 400) {
  const payload = {
    success : false,
    creator : 'ryysengtor',
    error   : message,
    channel : CHANNEL,
  };
  res
    .status(status)
    .type('application/json')
    .send(JSON.stringify(payload, null, 2));
}

module.exports = { rateLimitMiddleware, sendSuccessResponse, sendErrorResponse, CHANNEL };
