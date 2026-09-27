const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const path = require('path');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');

const { globalLimiter } = require('./middlewares/rateLimiter');

const app = express();

// V12: do not advertise the framework/version in responses (helmet also does
// this; kept explicit to document intent).
app.disable('x-powered-by');

// V9: trust the proxy hop(s) in front of the app so express-rate-limit keys on
// the real client IP, not the proxy's. Value comes from TRUST_PROXY (e.g. 1)
// rather than being hard-coded, so it matches the actual deployment topology.
if (process.env.TRUST_PROXY) {
  const tp = process.env.TRUST_PROXY;
  app.set('trust proxy', /^\d+$/.test(tp) ? Number(tp) : tp);
}

// V6: flat query strings only — ?a[$ne]=1 must never parse into an object.
// Express 5 already defaults to 'simple'; set explicitly to document intent.
app.set('query parser', 'simple');

// V12: security response headers — CSP, X-Content-Type-Options: nosniff,
// X-Frame-Options, Referrer-Policy, HSTS, etc. Mounted before routes so every
// response carries them.
app.use(helmet());

const swaggerDocument = YAML.load(path.join(__dirname, '../docs/swagger.yaml'));

const allowedOrigins = [
  process.env.ALLOWED_ORIGIN, // Your Vercel URL
  "http://localhost:5173",    // Vite Local 1
  "http://localhost:5174",    // Vite Local 2
  "http://localhost:3000"     // Standard Local
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = "The CORS policy for this site does not allow access from the specified Origin.";
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true
}));
app.use(express.json());
app.use(require('./middlewares/sanitize')); // V6: reject $-prefixed / dotted keys
// Required by the OAuth flow: the PKCE verifies.
app.use(cookieParser());
app.use(globalLimiter); // V9: broad per-IP request ceiling

// V12: Swagger UI documents the full API surface, so it is a development aid,
// not something to expose publicly. Serve it only in development (or when
// ENABLE_SWAGGER=true); it is off in production and under test. The UI needs a
// relaxed CSP for its own inline assets, applied only to this route.
const enableSwagger =
  process.env.ENABLE_SWAGGER === 'true' || process.env.NODE_ENV === 'development';
if (enableSwagger) {
  app.use(
    '/api-docs',
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
        },
      },
    }),
    swaggerUi.serve,
    swaggerUi.setup(swaggerDocument)
  );
}

app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/auth/oauth', require('./routes/oauthRoutes'));
app.use('/api/enforcements', require('./routes/enforcementRoutes'));
app.use('/api/hazards', require('./routes/hazardRoutes'));
app.use('/api/zones', require('./routes/zoneRoutes'));
app.use('/api/illegal-cases', require('./routes/illegalCaseRoutes'));
app.use('/api/reports', require('./routes/reportRoutes'));
app.use('/api/vessels', require('./routes/vesselRoutes'));
app.use('/api/translate', require('./routes/translationRoutes'));


app.get('/', (req, res) => {
  res.send('BlueShield API is running...');
});

// V14: must be last. Logs the full error server-side and returns a generic
// message, so exception text never reaches a client.
app.use(require('./middlewares/errorHandler'));

module.exports = app;
