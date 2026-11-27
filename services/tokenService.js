const crypto = require("node:crypto");

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;
const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;

class TokenError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "TokenError";
    this.code = code;
  }
}

function getTokenSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || Buffer.byteLength(secret, "utf8") < 32) {
    throw new TokenError(
      "JWT_SECRET must be configured with at least 32 characters",
      "AUTH_CONFIG_MISSING"
    );
  }
  return secret;
}

function encode(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function signToken(subject, type, ttlSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const header = encode({ alg: "HS256", typ: "JWT" });
  const payload = encode({
    sub: subject,
    tokenType: type,
    iat: now,
    exp: now + ttlSeconds,
    jti: crypto.randomUUID()
  });
  const content = `${header}.${payload}`;
  const signature = crypto
    .createHmac("sha256", getTokenSecret())
    .update(content)
    .digest("base64url");

  return `${content}.${signature}`;
}

function verifyToken(token, expectedType) {
  if (typeof token !== "string") {
    throw new TokenError("Invalid token", "TOKEN_INVALID");
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new TokenError("Invalid token", "TOKEN_INVALID");
  }

  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    throw new TokenError("Invalid token", "TOKEN_INVALID");
  }

  if (header.alg !== "HS256" || header.typ !== "JWT") {
    throw new TokenError("Invalid token", "TOKEN_INVALID");
  }

  const content = `${parts[0]}.${parts[1]}`;
  const expectedSignature = crypto
    .createHmac("sha256", getTokenSecret())
    .update(content)
    .digest();
  let actualSignature;
  try {
    actualSignature = Buffer.from(parts[2], "base64url");
  } catch {
    throw new TokenError("Invalid token", "TOKEN_INVALID");
  }

  if (
    actualSignature.length !== expectedSignature.length ||
    !crypto.timingSafeEqual(actualSignature, expectedSignature)
  ) {
    throw new TokenError("Invalid token", "TOKEN_INVALID");
  }

  if (
    typeof payload.sub !== "string" ||
    payload.tokenType !== expectedType ||
    !Number.isInteger(payload.exp)
  ) {
    throw new TokenError("Invalid token", "TOKEN_INVALID");
  }

  if (payload.exp <= Math.floor(Date.now() / 1000)) {
    throw new TokenError("Token expired", "TOKEN_EXPIRED");
  }

  return payload;
}

function createTokenPair(subject) {
  if (typeof subject !== "string" || subject.length === 0) {
    throw new TokenError("A token subject is required", "TOKEN_INVALID");
  }

  return {
    accessToken: signToken(subject, "access", ACCESS_TOKEN_TTL_SECONDS),
    refreshToken: signToken(subject, "refresh", REFRESH_TOKEN_TTL_SECONDS),
    tokenType: "Bearer",
    expiresIn: ACCESS_TOKEN_TTL_SECONDS,
    refreshExpiresIn: REFRESH_TOKEN_TTL_SECONDS
  };
}

function createAccessToken(subject) {
  return signToken(subject, "access", ACCESS_TOKEN_TTL_SECONDS);
}

module.exports = {
  TokenError,
  createAccessToken,
  createTokenPair,
  verifyToken,
  ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_TTL_SECONDS
};
