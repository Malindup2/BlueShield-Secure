// V6 — Reject MongoDB operator injection (CWE-943).
//
// Any key that starts with "$" (a query operator such as $ne, $gt, $where)
// or contains "." (a path into a sub-document) is refused with 400 before
// the request reaches a controller. Requests are rejected, not silently
// cleaned, so an attack attempt is visible rather than half-processed.
//
// express-mongo-sanitize is not used: it reassigns req.query, which is a
// read-only getter in Express 5 and throws on every request.
//
// The walk is iterative so a deeply nested body cannot exhaust the stack.

const isForbiddenKey = (key) => key.startsWith('$') || key.includes('.');

const findForbiddenKey = (root) => {
  const stack = [root];
  while (stack.length) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    for (const key of Object.keys(node)) {
      if (isForbiddenKey(key)) return key;
      stack.push(node[key]);
    }
  }
  return null;
};

module.exports = (req, res, next) => {
  if (findForbiddenKey(req.body) || findForbiddenKey(req.query)) {
    return res.status(400).json({ message: 'Request contains a disallowed key' });
  }
  next();
};
