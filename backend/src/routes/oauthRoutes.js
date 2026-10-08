const express = require('express');
const router = express.Router();

const {
  startGoogleAuth,
  googleCallback,
  exchangeSession,
} = require('../controllers/oauthController');

// The callback path must match the authorised redirect URI registered in
// the Google Cloud Console exactly.
router.get('/google', startGoogleAuth);
router.get('/google/callback', googleCallback);
router.post('/session', exchangeSession);

module.exports = router;
