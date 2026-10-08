# Security regression tests

One file per finding, named `vNN-<slug>.test.js` (e.g. `v06-nosql-injection.test.js`).

Each test reproduces the exploit from the findings register and asserts the
secure behaviour. Write it **before** the fix: it must fail on the vulnerable
code and pass once the fix lands. Capture both runs as before/after evidence.

```bash
npm run test:security          # this folder only
npm test                       # everything
```

`helpers.js` holds shared fixtures: common attack payloads and fake Mongoose
documents. Mock models with `jest.mock(...)` at the top of each test file —
Jest only hoists `jest.mock` calls that appear in the test file itself.
