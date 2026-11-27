const express = require("express");
const crypto = require("node:crypto");
const authenticate = require("../middleware/authenticate");
const {
  TokenError,
  createAccessToken,
  createTokenPair,
  verifyToken,
  ACCESS_TOKEN_TTL_SECONDS
} = require("../services/tokenService");

const router = express.Router();

function safeEqual(actual, expected) {
  const actualBuffer = Buffer.from(actual, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  return (
    actualBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(actualBuffer, expectedBuffer)
  );
}

router.post("/token", (req, res) => {
  const { API_CLIENT_ID, API_CLIENT_SECRET } = process.env;
  if (!API_CLIENT_ID || !API_CLIENT_SECRET) {
    return res.status(503).json({
      message: "Kredensial client API belum dikonfigurasi",
      code: "AUTH_CONFIG_MISSING"
    });
  }

  const { clientId, clientSecret } = req.body || {};
  const validClientId =
    typeof clientId === "string" && safeEqual(clientId, API_CLIENT_ID);
  const validClientSecret =
    typeof clientSecret === "string" &&
    safeEqual(clientSecret, API_CLIENT_SECRET);
  if (
    !validClientId ||
    !validClientSecret
  ) {
    return res.status(401).json({
      message: "Kredensial tidak valid",
      code: "INVALID_CREDENTIALS"
    });
  }

  try {
    return res.json(createTokenPair(API_CLIENT_ID));
  } catch (error) {
    if (error instanceof TokenError && error.code === "AUTH_CONFIG_MISSING") {
      return res.status(503).json({
        message: "Konfigurasi autentikasi server belum lengkap",
        code: error.code
      });
    }
    throw error;
  }
});

router.post("/refresh", (req, res) => {
  const { refreshToken } = req.body || {};
  try {
    const payload = verifyToken(refreshToken, "refresh");
    return res.json({
      accessToken: createAccessToken(payload.sub),
      tokenType: "Bearer",
      expiresIn: ACCESS_TOKEN_TTL_SECONDS
    });
  } catch (error) {
    if (error instanceof TokenError && error.code === "AUTH_CONFIG_MISSING") {
      return res.status(503).json({
        message: "Konfigurasi autentikasi server belum lengkap",
        code: error.code
      });
    }
    return res.status(401).json({
      message:
        error instanceof TokenError && error.code === "TOKEN_EXPIRED"
          ? "Refresh token kedaluwarsa"
          : "Refresh token tidak valid",
      code:
        error instanceof TokenError && error.code === "TOKEN_EXPIRED"
          ? "TOKEN_EXPIRED"
          : "TOKEN_INVALID"
    });
  }
});

router.get("/me", authenticate, (req, res) => {
  res.json({ id: req.auth.sub });
});

module.exports = router;
