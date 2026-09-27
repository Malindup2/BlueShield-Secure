require('dotenv').config();
const connectDB = require('./src/config/db');

//hotfix on Anjulas Device - DNS resolution issue - not connecting to MongoDB Atlas cluster, added custom DNS servers (Cloudflare and Google) to bypass local DNS issues. This is a temporary workaround until the underlying DNS issue is resolved on the device.
const dns = require("dns");
dns.setServers(["1.1.1.1", "8.8.8.8"]);
//hotfix end

const app = require('./src/app');
const fs = require('fs');
const http = require('http');
const https = require('https');

connectDB();

const PORT = process.env.PORT || 5000;
const MODE = process.env.NODE_ENV || 'development';

// V17 — Transport security (OWASP A02:2021, CWE-319/311).
// If a TLS key/cert pair is configured, serve the API over HTTPS restricted to
// TLS 1.2+ (POODLE/legacy-protocol mitigation) and run a tiny HTTP listener
// that 301-redirects everything to HTTPS. If no cert is configured — e.g. a
// deployment where TLS is terminated by a proxy/load balancer — fall back to a
// plain HTTP listener (the proxy provides TLS, and enforceHttps + HSTS still
// apply via X-Forwarded-Proto).
const keyPath = process.env.TLS_KEY_PATH;
const certPath = process.env.TLS_CERT_PATH;
const tlsConfigured = keyPath && certPath && fs.existsSync(keyPath) && fs.existsSync(certPath);

if (tlsConfigured) {
  const httpsOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
    minVersion: 'TLSv1.2', // disable SSLv3/TLS1.0/1.1 (POODLE, weak ciphers)
  };

  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(`Server running in ${MODE} mode over HTTPS (TLS 1.2+) on port ${PORT}`);
  });

  // Redirect plaintext HTTP to HTTPS.
  const httpRedirectPort = process.env.HTTP_REDIRECT_PORT || 8080;
  http
    .createServer((req, res) => {
      const host = (req.headers.host || `localhost:${PORT}`).replace(/:\d+$/, `:${PORT}`);
      res.writeHead(301, { Location: `https://${host}${req.url}` });
      res.end();
    })
    .listen(httpRedirectPort, () => {
      console.log(`HTTP->HTTPS redirect listener on port ${httpRedirectPort}`);
    });
} else {
  app.listen(PORT, () => {
    console.log(`Server running in ${MODE} mode on port ${PORT} (plain HTTP — TLS expected at the proxy)`);
  });
}

module.exports = app;