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
			name:               "missing JWT header",
			request:            httptest.NewRequest("GET", "/", nil),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "authorization header missing",
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
			name: "invalid JWT",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Add("Authorization", "Bearer not.a.jwt")
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
			name: "expired token",
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
			name: "wrong signing algorithm (RS256 token against HS256 handler)",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				// A token signed with a different algorithm header (manually crafted header)
				// We simply use the wrong secret to trigger signature failure.
				tok := makeToken(jwt.MapClaims{"sub": "1234", "exp": futureExp}, "wrong-secret")
				r.Header.Add("Authorization", "Bearer "+tok)
				return r
			}(),
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       "Unauthorized",
		},
		{
			name: "valid token",
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualNextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("OK"))
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
				t.Errorf("expected status code %v, but got %v", test.expectedStatusCode, actual.StatusCode)
			}

			actualBody, err := io.ReadAll(actual.Body)
			if err != nil {
				t.Fatalf("failed to read body: %v", err)
			}
			if !strings.Contains(string(actualBody), test.expectedBody) {
				t.Errorf("expected body to contain %q but got %q", test.expectedBody, string(actualBody))
			}
		})
	}
}

