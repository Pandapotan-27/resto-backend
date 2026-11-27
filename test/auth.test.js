const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { after, before, test } = require("node:test");

process.env.JWT_SECRET = "test-secret-with-more-than-32-characters";
process.env.API_CLIENT_ID = "test-client";
process.env.API_CLIENT_SECRET = "test-client-secret";

const app = require("../index");
const { ACCESS_TOKEN_TTL_SECONDS } = require("../services/tokenService");

let server;
let baseUrl;

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://localhost:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

function createExpiredAccessToken(subject) {
  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const header = encode({ alg: "HS256", typ: "JWT" });
  const payload = encode({
    sub: subject,
    tokenType: "access",
    iat: 1,
    exp: Math.floor(Date.now() / 1000) - 1
  });
  const content = `${header}.${payload}`;
  const signature = crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(content)
    .digest("base64url");
  return `${content}.${signature}`;
}

test("API requires Bearer tokens and automatically renews expired access tokens", async () => {
  const unauthorized = await fetch(`${baseUrl}/api/auth/me`);
  assert.equal(unauthorized.status, 401);

  const tokenResponse = await fetch(`${baseUrl}/api/auth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      clientId: process.env.API_CLIENT_ID,
      clientSecret: process.env.API_CLIENT_SECRET
    })
  });
  assert.equal(tokenResponse.status, 200);
  const tokens = await tokenResponse.json();
  assert.equal(tokens.expiresIn, ACCESS_TOKEN_TTL_SECONDS);

  const accessPayload = JSON.parse(
    Buffer.from(tokens.accessToken.split(".")[1], "base64url").toString("utf8")
  );
  assert.ok(accessPayload.exp > accessPayload.iat);

  const renewedResponse = await fetch(`${baseUrl}/api/auth/me`, {
    headers: {
      authorization: `Bearer ${createExpiredAccessToken(process.env.API_CLIENT_ID)}`,
      "x-refresh-token": tokens.refreshToken
    }
  });
  assert.equal(renewedResponse.status, 200);
  assert.equal(renewedResponse.headers.get("x-token-refreshed"), "true");
  assert.ok(renewedResponse.headers.get("x-access-token"));
  assert.deepEqual(await renewedResponse.json(), {
    id: process.env.API_CLIENT_ID
  });

  const protectedUnknownRoute = await fetch(`${baseUrl}/api/unknown`, {
    headers: { authorization: `Bearer ${tokens.accessToken}` }
  });
  assert.equal(protectedUnknownRoute.status, 404);
});
