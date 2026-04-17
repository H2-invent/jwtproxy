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
	}{
		// ── Token extraction errors ───────────────────────────────────────────
		{
			name:               "missing token (no header, no query param)",
			request:            httptest.NewRequest("GET", "/test/abc", nil),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "token missing",
		},
		{
			name: "junk format for authorization header",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/test/abc", nil)
				r.Header.Add("Authorization", "nonsense")
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "authorization header must be 'Bearer <token>'",
		},
		{
			name: "invalid JWT via header",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/test/abc", nil)
				r.Header.Add("Authorization", "Bearer not.a.jwt")
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Unauthorized",
		},
		{
			name: "invalid JWT via query param",
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/test/abc?token=not.a.jwt", nil)
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Unauthorized",
		},
		{
			name: "missing exp claim",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/test/abc", nil)
				tok := makeToken(jwt.MapClaims{"sub": "1234", "path": "/test/abc"}, testSecret)
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Unauthorized",
		},
		{
			name: "expired token",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/test/abc", nil)
				tok := makeToken(jwt.MapClaims{"exp": pastExp, "path": "/test/abc"}, testSecret)
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Unauthorized",
		},
		{
			name: "wrong secret",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/test/abc", nil)
				tok := makeToken(jwt.MapClaims{"exp": futureExp, "path": "/test/abc"}, "wrong-secret")
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Unauthorized",
		},
		// ── Path claim errors ─────────────────────────────────────────────────
		{
			name: "missing path claim",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/test/abc", nil)
				tok := makeToken(jwt.MapClaims{"exp": futureExp}, testSecret)
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusForbidden,
			expectedBody:       "path claim missing",
		},
		{
			name: "path mismatch – different path",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/test/abc", nil)
				tok := makeToken(jwt.MapClaims{"exp": futureExp, "path": "/other/path"}, testSecret)
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusForbidden,
			expectedBody:       "request path does not match token path",
		},
		{
			name: "path mismatch – trailing slash",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/test/abc/", nil)
				tok := makeToken(jwt.MapClaims{"exp": futureExp, "path": "/test/abc"}, testSecret)
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusForbidden,
			expectedBody:       "request path does not match token path",
		},
		// ── Valid requests ────────────────────────────────────────────────────
		{
			name: "valid token with correct path via header",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/test/abc", nil)
				tok := makeToken(jwt.MapClaims{"exp": futureExp, "path": "/test/abc"}, testSecret)
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusOK,
			expectedBody:       "OK",
			expectedNextCalled: true,
		},
		{
			name: "valid token with correct path via ?token= query param",
			request: func() *http.Request {
				tok := makeToken(jwt.MapClaims{"exp": futureExp, "path": "/test/abc"}, testSecret)
				return httptest.NewRequest("GET", "/test/abc?token="+tok, nil)
			}(),
			expectedStatusCode: http.StatusOK,
			expectedBody:       "OK",
			expectedNextCalled: true,
		},
		{
			name: "?token= is stripped before forwarding, other params preserved",
			request: func() *http.Request {
				tok := makeToken(jwt.MapClaims{"exp": futureExp, "path": "/test/abc"}, testSecret)
				return httptest.NewRequest("GET", "/test/abc?foo=bar&token="+tok, nil)
			}(),
			expectedStatusCode: http.StatusOK,
			expectedBody:       "foo=bar",
			expectedNextCalled: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualNextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actualNextCalled = true
				// Echo raw query string so we can assert param stripping;
				// fall back to "OK" when no query string is present.
				if r.URL.RawQuery != "" {
					w.Write([]byte(r.URL.RawQuery))
				} else {
					w.Write([]byte("OK"))
				}
			})

			handler := NewJWTAuthHandler([]byte(testSecret), time.Now, next)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, test.request)

			actual := recorder.Result()

			if test.expectedNextCalled != actualNextCalled {
				t.Errorf("expected next called %v, got %v", test.expectedNextCalled, actualNextCalled)
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
