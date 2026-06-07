package ui

import (
	"net/http"
	"time"
)

// SetSessionCookie writes a session cookie to w. The positive MaxAge is derived
// from expires so the browser honours the expiry even without a real-time clock.
func SetSessionCookie(w http.ResponseWriter, rawToken string, expires time.Time, cfg CookieConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Name,
		Value:    rawToken,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
	})
}

// ClearSessionCookie writes a cookie that instructs the browser to delete the
// session cookie immediately. MaxAge=-1 is the standard deletion signal.
func ClearSessionCookie(w http.ResponseWriter, cfg CookieConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
	})
}
