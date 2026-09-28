package github

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestAssertion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	synctest.Test(t, func(t *testing.T) {
		const ttl = 9 * time.Minute
		start := time.Now()

		got, err := assertion(key, "1234567", ttl)
		if err != nil {
			t.Fatal(err)
		}

		parts := strings.Split(got, ".")
		if len(parts) != 3 {
			t.Fatalf("got %d segments, want 3: %s", len(parts), got)
		}

		header, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"alg":"RS256","typ":"JWT"}`; string(header) != want {
			t.Errorf("header is %s, want %s", header, want)
		}

		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Iss string `json:"iss"`
			Iat int64  `json:"iat"`
			Exp int64  `json:"exp"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		if claims.Iss != "1234567" {
			t.Errorf("iss is %q, want %q", claims.Iss, "1234567")
		}
		if want := start.Add(-time.Minute).Unix(); claims.Iat != want {
			t.Errorf("iat is %d, want %d", claims.Iat, want)
		}
		if want := start.Add(ttl).Unix(); claims.Exp != want {
			t.Errorf("exp is %d, want %d", claims.Exp, want)
		}

		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
			t.Errorf("the signature does not verify: %v", err)
		}
	})
}
