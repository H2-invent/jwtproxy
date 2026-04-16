package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "super-secret-key-for-tests"

// makeToken creates a signed HS256 token with the given claims and secret.
func makeToken(claims jwt.MapClaims, secret string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		panic(err)
	}
	return signed
}

func TestJWTHandling(t *testing.T) {
	futureExp := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	pastExp := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	tests := []struct {
		name               string
		request            *http.Request
		expectedStatusCode int
		expectedBody       string
		expectedNextCalled bool
		now                func() time.Time
	}{
		{
			name:               "missing token (no header, no query param)",
			request:            httptest.NewRequest("GET", "/", nil),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "token missing",
		},
		{
			name: "junk format for authorization header",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Add("Authorization", "nonsense")
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "authorization header must be 'Bearer <token>'",
		},
		{
			name: "invalid JWT via header",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Add("Authorization", "Bearer not.a.jwt")
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Unauthorized",
		},
		{
			name: "invalid JWT via query param",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/?jwt=not.a.jwt", nil)
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Unauthorized",
		},
		{
			name: "missing exp claim",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				tok := makeToken(jwt.MapClaims{"sub": "1234"}, testSecret)
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Unauthorized",
		},
		{
			name: "expired token via header",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				tok := makeToken(jwt.MapClaims{"sub": "1234", "exp": pastExp}, testSecret)
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Unauthorized",
		},
		{
			name: "wrong secret",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				tok := makeToken(jwt.MapClaims{"sub": "1234", "exp": futureExp}, "wrong-secret")
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Unauthorized",
		},
		// ── Valid tokens ──────────────────────────────────────────────────────
		{
			name: "valid token via Authorization header",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				tok := makeToken(jwt.MapClaims{"sub": "1234", "exp": futureExp}, testSecret)
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusOK,
			expectedBody:       "OK",
			expectedNextCalled: true,
		},
		{
			name: "valid token via ?jwt= query param",
			request: func() *http.Request {
				tok := makeToken(jwt.MapClaims{"sub": "1234", "exp": futureExp}, testSecret)
				r := httptest.NewRequest("GET", "/?jwt="+tok, nil)
				return r
			}(),
			expectedStatusCode: http.StatusOK,
			expectedBody:       "OK",
			expectedNextCalled: true,
		},
		{
			name: "?jwt= is stripped before forwarding to backend",
			request: func() *http.Request {
				tok := makeToken(jwt.MapClaims{"sub": "1234", "exp": futureExp}, testSecret)
				r := httptest.NewRequest("GET", "/path?foo=bar&jwt="+tok, nil)
				return r
			}(),
			expectedStatusCode: http.StatusOK,
			expectedBody:       "foo=bar", // backend receives only foo=bar, no jwt=
			expectedNextCalled: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualNextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Echo back the raw query string so we can assert stripping.
				w.Write([]byte(r.URL.RawQuery))
				if r.URL.RawQuery == "" {
					w.Write([]byte("OK"))
				}
				actualNextCalled = true
			})

			now := time.Now
			if test.now != nil {
				now = test.now
			}

			handler := NewJWTAuthHandler([]byte(testSecret), now, next)
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, test.request)

			actual := recorder.Result()

			if test.expectedNextCalled != actualNextCalled {
				t.Errorf("expected next called %v, but got %v", test.expectedNextCalled, actualNextCalled)
			}
			if actual.StatusCode != test.expectedStatusCode {
				t.Errorf("expected status %v, got %v", test.expectedStatusCode, actual.StatusCode)
			}
			body, _ := io.ReadAll(actual.Body)
			if !strings.Contains(string(body), test.expectedBody) {
				t.Errorf("expected body to contain %q, got %q", test.expectedBody, string(body))
			}
		})
	}
}
