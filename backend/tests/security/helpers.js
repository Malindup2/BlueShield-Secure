// Shared fixtures for the security regression suite.

// MongoDB query operators an attacker can smuggle in through a JSON body.
const OPERATOR_PAYLOADS = {
  ne: { $ne: null },
  gt: { $gt: '' },
  regex: { $regex: '.*' },
};

// A fake User document as returned by User.findOne(...).select('+password').
// matchPassword resolves to `passwordMatches`, so a test can model an
// operator payload that the database would have matched.
const fakeUser = ({ passwordMatches = true, ...overrides } = {}) => ({
  _id: 'user-1',
  id: 'user-1',
  name: 'Nimal',
  email: 'nimal@example.com',
  role: 'FISHERMAN',
  matchPassword: jest.fn().mockResolvedValue(passwordMatches),
  save: jest.fn().mockResolvedValue(undefined),
  ...overrides,
});

// User.findOne is chained with .select() in loginUser but awaited directly
// elsewhere; this stub supports both call styles.
const findOneResult = (doc) => {
  const promise = Promise.resolve(doc);
  promise.select = jest.fn().mockResolvedValue(doc);
  return promise;
};

module.exports = { OPERATOR_PAYLOADS, fakeUser, findOneResult };
