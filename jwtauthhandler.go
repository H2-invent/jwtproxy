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
	tokenString, err := extractBearerToken(r)
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

	h.Next.ServeHTTP(w, r)
}

// extractBearerToken pulls the raw JWT string out of the Authorization header.
func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header missing")
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", errors.New("authorization header must be 'Bearer <token>'")
	}
	return strings.TrimSpace(parts[1]), nil
}
