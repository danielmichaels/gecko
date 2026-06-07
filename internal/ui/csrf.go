package ui

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

// CSRFHeader is the request header browsers/JS must send for state-mutating
// requests. Using a custom header provides CSRF protection without a form
// hidden-field because cross-origin simple requests cannot set custom headers.
const CSRFHeader = "X-CSRF-Token"

// csrfToken derives a per-session CSRF token by HMAC-SHA256-keying the raw
// session token. Binding the CSRF token to the session means rotating the
// session automatically invalidates the CSRF token.
func csrfToken(key []byte, raw string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// safeMethods are HTTP methods that do not mutate state; CSRF validation is
// skipped for them.
var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
}

// CSRFValidate rejects state-mutating requests whose X-CSRF-Token header does
// not match the expected per-session token. It must be composed inside WebAuth
// so the session cookie and context principal are already available.
func (a *App) CSRFValidate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if safeMethods[r.Method] {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(a.cookieCfg.Name)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		expected := csrfToken(a.csrfKey, cookie.Value)
		got := r.Header.Get(CSRFHeader)

		// Constant-time comparison prevents timing side-channels that could
		// reveal bytes of the expected token to an attacker probing response latency.
		if subtle.ConstantTimeCompare([]byte(expected), []byte(got)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
