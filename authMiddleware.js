const jwt = require("jsonwebtoken");

module.exports = function authMiddleware(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  const authHeader = req.headers["authorization"] || "";

  // 1. API Key Auth
  if (apiKey && apiKey === process.env.API_KEY) {
    req.authType = "api-key";
    return next();
  }

  // 2. Basic Auth
  if (authHeader.startsWith("Basic ")) {
    const base64 = authHeader.split(" ")[1];
    const [username, password] = Buffer.from(base64, "base64")
      .toString()
      .split(":");
    if (
      username === process.env.BASIC_USER &&
      password === process.env.BASIC_PASS
    ) {
      req.authType = "basic-auth";
      return next();
    }
  }

  // 3. OAuth2 (Bearer Token) - Method 1
  if (authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    try {
      const payload = jwt.verify(token, process.env.OAUTH_SECRET);
      req.authType = "oauth2-bearer";
      req.tokenPayload = payload;
      return next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid bearer token" });
    }
  }

  // 4. OAuth2 (ClientId + ClientSecret) - Method 2 (via headers)
  const clientId = req.headers["clientid"];
  const clientSecret = req.headers["clientsecret"];

  if (clientId && clientSecret) {
    if (clientId === process.env.OAUTH_CLIENT && clientSecret === process.env.OAUTH_SECRET) {
      const token = jwt.sign({ client: clientId }, process.env.OAUTH_SECRET, { expiresIn: "1h" });
      req.authType = "oauth2-client";
      req.accessToken = token;
      return next();
    } else {
      return res.status(401).json({ error: "Invalid client credentials" });
    }
  }

  // If no valid auth method is found, return Unauthorized
  return res.status(401).json({ error: "Unauthorized" });
};
