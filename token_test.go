package kc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

//----------------------------------------------------------------------------------------------------------------------------//

func TestParseToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)

	ah := &AuthHandler{kcPubKey: &key.PublicKey}

	exp := time.Now().Add(time.Hour).Unix()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"exp": exp, "azp": "idc", "acr": "1", "aud": "account", "preferred_username": "u1"}
	}

	sign := func(m jwt.SigningMethod, k any, c jwt.MapClaims) string {
		s, err := jwt.NewWithClaims(m, c).SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	noExp := base()
	delete(noExp, "exp")
	expired := base()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()

	// HS256 с открытым ключом kc в роли секрета - классическая подмена alg
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)

	cases := []struct {
		name  string
		token string
		ok    bool
	}{
		{"RS256", sign(jwt.SigningMethodRS256, key, base()), true},
		{"RS512", sign(jwt.SigningMethodRS512, key, base()), true},
		{"aud of another client is not checked", sign(jwt.SigningMethodRS256, key, base()), true},
		{"other key", sign(jwt.SigningMethodRS256, other, base()), false},
		{"no exp", sign(jwt.SigningMethodRS256, key, noExp), false},
		{"expired", sign(jwt.SigningMethodRS256, key, expired), false},
		{"HS256 with public key as secret", sign(jwt.SigningMethodHS256, pubDER, base()), false},
	}

	for _, c := range cases {
		dst := jwt.MapClaims{}
		err := ah.parseToken(c.token, dst)
		if c.ok && err != nil {
			t.Errorf(`%s: %s`, c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf(`%s: expected error`, c.name)
		}
		if c.ok && dst["azp"] != "idc" {
			t.Errorf(`%s: claims not filled: %v`, c.name, dst)
		}
	}
}

//----------------------------------------------------------------------------------------------------------------------------//
