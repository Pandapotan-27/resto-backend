const {
  TokenError,
  createAccessToken,
  verifyToken
} = require("../services/tokenService");

function authenticate(req, res, next) {
  const authorization = req.get("authorization");
  const match = authorization && authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({
      message: "Access token tidak ditemukan",
      code: "TOKEN_REQUIRED"
    });
  }

  try {
    const accessToken = match[1];
    try {
      req.auth = verifyToken(accessToken, "access");
    } catch (error) {
      if (!(error instanceof TokenError) || error.code !== "TOKEN_EXPIRED") {
        throw error;
      }

      const refreshToken = req.get("x-refresh-token");
      if (!refreshToken) {
        throw error;
      }

      const refreshPayload = verifyToken(refreshToken, "refresh");
      const renewedAccessToken = createAccessToken(refreshPayload.sub);
      req.auth = {
        sub: refreshPayload.sub,
        tokenType: "access"
      };
      res.set("X-Access-Token", renewedAccessToken);
      res.set("X-Token-Refreshed", "true");
    }

    return next();
  } catch (error) {
    if (error instanceof TokenError && error.code === "AUTH_CONFIG_MISSING") {
      return res.status(503).json({
        message: "Konfigurasi autentikasi server belum lengkap",
        code: error.code
      });
    }

    const expired = error instanceof TokenError && error.code === "TOKEN_EXPIRED";
    return res.status(401).json({
      message: expired ? "Access token kedaluwarsa" : "Token tidak valid",
      code: expired ? "TOKEN_EXPIRED" : "TOKEN_INVALID"
    });
  }
}

module.exports = authenticate;
