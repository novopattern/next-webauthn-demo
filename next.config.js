/** @type {import('next').NextConfig} */
// next.config.js
const withTM = require('next-transpile-modules')(['@simplewebauthn/browser']); // pass the modules you would like to see transpiled

module.exports = withTM({
  reactStrictMode: true,
});