package main

import (
	"os"
	"testing"
)

func TestThatPathsAreJoinedWithASlash(t *testing.T) {
	tests := []struct {
		a        string
		b        string
		expected string
	}{
		{
			a:        "/test/",
			b:        "/b/",
			expected: "/test/b/",
		},
		{
			a:        "test",
			b:        "b",
			expected: "test/b",
		},
		{
			a:        "test",
			b:        "/b",
			expected: "test/b",
		},
		{
			a:        "test/",
			b:        "b",
			expected: "test/b",
		},
	}

	for _, test := range tests {
		actual := singleJoiningSlash(test.a, test.b)
		if actual != test.expected {
			t.Errorf("for '%v' and '%v', expected '%v' got '%v'", test.a, test.b, test.expected, actual)
		}
	}
}

func TestGetSecretFromFlag(t *testing.T) {
	*secretFlag = "my-flag-secret"
	defer func() { *secretFlag = "" }()

	secret, err := getSecret()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != "my-flag-secret" {
		t.Errorf("expected 'my-flag-secret', got '%v'", secret)
	}
}

func TestGetSecretFromEnv(t *testing.T) {
	os.Setenv("JWTPROXY_SECRET", "my-env-secret")
	defer os.Unsetenv("JWTPROXY_SECRET")

	secret, err := getSecret()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != "my-env-secret" {
		t.Errorf("expected 'my-env-secret', got '%v'", secret)
	}
}

func TestGetSecretMissing(t *testing.T) {
	os.Unsetenv("JWTPROXY_SECRET")
	*secretFlag = ""

	_, err := getSecret()
	if err == nil {
		t.Error("expected error when secret is missing")
	}
}

