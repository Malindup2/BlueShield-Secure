// V14 — central error handling.
//
// Controllers previously answered failures with res.status(500).json({
// message: error.message }), returning Mongoose and driver text straight to
// the caller: collection names, connection strings, duplicate-key details
// and cast errors. Full detail is logged server-side instead, and the client
// receives a generic message.

const logger = require('../utils/logger');

// eslint-disable-next-line no-unused-vars -- Express identifies the error
// handler by its four-parameter signature.
module.exports = (err, req, res, next) => {
  logger.serverError(req, err);

  if (res.headersSent) return next(err);

  // Known client-side failures keep their status but not their detail.
  const status = err.statusCode || err.status || 500;

  const message =
    status < 500
      ? err.expose === true && err.message
        ? err.message
        : 'Request could not be processed'
      : 'An unexpected error occurred. Please try again later.';

  res.status(status).json({ message });
};
