package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTAuthHandler provides the capability to authenticate incoming HTTP requests
// using a shared HMAC secret (HS256).
type JWTAuthHandler struct {
	Secret []byte
	Next   http.Handler
	Now    func() time.Time
}

// NewJWTAuthHandler creates a new JWTAuthHandler, passing in an HMAC secret
// and a time provider to allow for variation of the time.
func NewJWTAuthHandler(secret []byte, now func() time.Time, next http.Handler) JWTAuthHandler {
	return JWTAuthHandler{
		Secret: secret,
		Next:   next,
		Now:    now,
	}
}

func (h JWTAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tokenString, fromQuery, err := extractToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Enforce HS256 – reject any other signing method to prevent algorithm-confusion attacks.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return h.Secret, nil
	}, jwt.WithTimeFunc(h.Now), jwt.WithExpirationRequired())

	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Strip the ?jwt= parameter before forwarding so the backend never sees it.
	if fromQuery {
		stripJWTQueryParam(r)
	}

	h.Next.ServeHTTP(w, r)
}

// extractToken looks for a JWT in this order:
//  1. Query parameter ?jwt=...
//  2. Authorization: Bearer ... header
//
// Returns the raw token string and a flag indicating whether it came from the query.
func extractToken(r *http.Request) (token string, fromQuery bool, err error) {
	if t := r.URL.Query().Get("jwt"); t != "" {
		return t, true, nil
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", false, errors.New("token missing: provide ?jwt=... or Authorization: Bearer <token>")
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", false, errors.New("authorization header must be 'Bearer <token>'")
	}
	return strings.TrimSpace(parts[1]), false, nil
}

// stripJWTQueryParam removes the jwt query parameter from the request URL
// so that the upstream backend never receives it.
func stripJWTQueryParam(r *http.Request) {
	q := r.URL.Query()
	q.Del("jwt")
	r.URL.RawQuery = q.Encode()
}
