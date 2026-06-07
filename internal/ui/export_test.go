package ui

// ExportedCSRFToken exposes the private csrfToken function to the external
// test package so tests can compute the expected token without making it public API.
var ExportedCSRFToken = csrfToken
