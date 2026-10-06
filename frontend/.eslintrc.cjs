// Phase 0 baseline (2026-10-06): the repo shipped `eslint` with no config file,
// so `npm run lint` failed with "couldn't find a configuration file". This
// minimal config (eslint:recommended + typescript recommended, `any` allowed)
// passes on the current codebase; tighten rules incrementally in Phase 1.
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
  env: { browser: true, es2020: true },
  ignorePatterns: ['dist', 'node_modules'],
  rules: {
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
  },
}
