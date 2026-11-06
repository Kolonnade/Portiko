package verify_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/Kolonnade/Portiko/verify"
	"github.com/Kolonnade/Portiko/verify/verifytest"
)

// F1: tokens carrying unknown key ids must not turn a relying party into a
// request amplifier aimed at the provider.
func TestUnknownKeyIDsDoNotAmplifyFetches(t *testing.T) {
	var fetches atomic.Int32
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &priv.PublicKey, KeyID: "real", Algorithm: "ES256", Use: "sig"},
		}})
	}))
	defer srv.Close()

	ks := verify.NewKeySet(srv.URL, nil)
	ctx := context.Background()
	if _, err := ks.Key(ctx, "real"); err != nil {
		t.Fatalf("known key: %v", err)
	}
	for i := 0; i < 200; i++ {
		if _, err := ks.Key(ctx, fmt.Sprintf("forged-%d", i)); err == nil {
			t.Fatal("an unknown kid resolved to a key")
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d fetches for 200 unknown kids, want 1", n)
	}

	// A real rotation is still picked up once the interval has passed.
	ks.SetMinInterval(10 * time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	_, _ = ks.Key(ctx, "rotated")
	if n := fetches.Load(); n != 2 {
		t.Fatalf("after the interval: %d fetches, want 2", n)
	}
}

// A token must carry exactly one audience and the expected type.
func TestTokenChecksAudienceAndType(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &priv.PublicKey, KeyID: "k", Algorithm: "ES256", Use: "sig"},
		}})
	}))
	defer srv.Close()

	sign := func(typ string, aud any) string {
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: &jose.JSONWebKey{Key: priv, KeyID: "k"}},
			(&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
		payload, _ := json.Marshal(map[string]any{
			"iss": "https://issuer", "sub": "usr_1", "aud": aud, "exp": time.Now().Add(time.Minute).Unix(),
		})
		obj, _ := signer.Sign(payload)
		s, _ := obj.CompactSerialize()
		return s
	}
	opts := verify.Options{Issuer: "https://issuer", Audience: "groups", Keys: verify.NewKeySet(srv.URL, nil), Type: "logout+jwt"}
	ctx := context.Background()

	if _, err := verify.Token(ctx, sign("logout+jwt", "groups"), opts); err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if _, err := verify.Token(ctx, sign("JWT", "groups"), opts); !errors.Is(err, verify.ErrType) {
		t.Errorf("a token of the wrong type: %v, want ErrType", err)
	}
	if _, err := verify.Token(ctx, sign("logout+jwt", []string{"groups", "photos"}), opts); !errors.Is(err, verify.ErrAudience) {
		t.Errorf("a token with two audiences: %v, want ErrAudience", err)
	}
	if _, err := verify.Token(ctx, sign("logout+jwt", "photos"), opts); !errors.Is(err, verify.ErrAudience) {
		t.Errorf("a token for another audience: %v, want ErrAudience", err)
	}
}

func set(k string, v any) func(map[string]any) { return func(m map[string]any) { m[k] = v } }
func del(k string) func(map[string]any)        { return func(m map[string]any) { delete(m, k) } }

func check(t *testing.T, p *verifytest.Provider, token string, want error) *verify.Claims {
	t.Helper()
	c, err := p.Verifier().Verify(context.Background(), token)
	if want == nil {
		if err != nil {
			t.Fatalf("valid token refused: %v", err)
		}
		return c
	}
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
	return nil
}

func TestAccessTokenValid(t *testing.T) {
	p := verifytest.NewProvider(t)
	c := check(t, p, p.AccessToken(t, "usr_1"), nil)
	if c.Subject != "usr_1" || c.SessionID != "sid-usr_1" || c.TokenID != "tok-usr_1" {
		t.Errorf("claims not mapped: %+v", c)
	}
	if time.Until(c.ExpiresAt) < 14*time.Minute {
		t.Errorf("ExpiresAt %s not mapped", c.ExpiresAt)
	}
}

func TestAccessTokenSingleStringAudience(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.AccessToken(t, "usr_1", set("aud", verifytest.Audience)), nil)
}

func TestAccessTokenAcceptsAtJWT(t *testing.T) {
	p := verifytest.NewProvider(t)
	claims := map[string]any{
		"iss": p.Issuer(), "sub": "usr_1", "aud": verifytest.Audience, "jti": "j",
		"exp": time.Now().Add(time.Minute).Unix(),
	}
	check(t, p, p.Sign(t, "at+jwt", verifytest.KeyID, claims), nil)
}

func TestAccessTokenRejectsAlgNone(t *testing.T) {
	p := verifytest.NewProvider(t)
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"none","typ":"JWT","kid":"` + verifytest.KeyID + `"}`))
	payload := strings.Split(p.AccessToken(t, "usr_1"), ".")[1]
	check(t, p, header+"."+payload+".", verify.ErrMalformed)
}

func TestAccessTokenRejectsHS256(t *testing.T) {
	p := verifytest.NewProvider(t)
	// The classic confusion: an HMAC keyed with the public key's own published
	// form, which any attacker can fetch.
	pub, err := json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "kid": verifytest.KeyID,
		"x": strings.Repeat("A", 43), "y": strings.Repeat("B", 43)})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: &jose.JSONWebKey{Key: pub, KeyID: verifytest.KeyID}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(p.AccessToken(t, "usr_1"), ".")[1])
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := obj.CompactSerialize()
	check(t, p, s, verify.ErrMalformed)
}

func TestAccessTokenRejectsWrongIssuer(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.AccessToken(t, "usr_1", set("iss", "https://elsewhere")), verify.ErrIssuer)
}

func TestAccessTokenRejectsWrongAudience(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.AccessToken(t, "usr_1", set("aud", []any{"other"})), verify.ErrAudience)
}

func TestAccessTokenRejectsTwoAudiences(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.AccessToken(t, "usr_1", set("aud", []any{verifytest.Audience, "other"})), verify.ErrAudience)
}

func TestAccessTokenRejectsMissingAudience(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.AccessToken(t, "usr_1", del("aud")), verify.ErrAudience)
}

func TestAccessTokenRejectsExpired(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.AccessToken(t, "usr_1", set("exp", time.Now().Add(-2*time.Minute).Unix())), verify.ErrExpired)
}

func TestAccessTokenAllowsSkew(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.AccessToken(t, "usr_1", set("exp", time.Now().Add(-30*time.Second).Unix())), nil)
}

func TestAccessTokenRejectsMissingExpiry(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.AccessToken(t, "usr_1", del("exp")), verify.ErrMissingClaim)
}

func TestAccessTokenRejectsFutureIssuedAt(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.AccessToken(t, "usr_1", set("iat", time.Now().Add(5*time.Minute).Unix())), verify.ErrNotYetValid)
}

func TestAccessTokenRejectsFutureNotBefore(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.AccessToken(t, "usr_1", set("nbf", time.Now().Add(5*time.Minute).Unix())), verify.ErrNotYetValid)
}

func TestAccessTokenRejectsIDToken(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.IDToken(t, "usr_1"), verify.ErrNotAccessToken)
}

func TestAccessTokenRejectsEachIDTokenMarker(t *testing.T) {
	p := verifytest.NewProvider(t)
	for _, k := range []string{"at_hash", "c_hash", "azp", "nonce"} {
		t.Run(k, func(t *testing.T) {
			check(t, p, p.AccessToken(t, "usr_1", set(k, "x")), verify.ErrNotAccessToken)
		})
	}
}

func TestAccessTokenRequiresJTI(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.AccessToken(t, "usr_1", del("jti")), verify.ErrMissingClaim)
}

func TestAccessTokenDoesNotRequireScope(t *testing.T) {
	p := verifytest.NewProvider(t)
	c := check(t, p, p.AccessToken(t, "usr_1", del("scope")), nil)
	if c.Scope != "" {
		t.Errorf("Scope %q, want empty", c.Scope)
	}
}

func TestAccessTokenRejectsOpaqueRefreshToken(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.RefreshToken(t), verify.ErrMalformed)
}

func TestAccessTokenRejectsJWTRefreshToken(t *testing.T) {
	p := verifytest.NewProvider(t)
	claims := map[string]any{
		"iss": p.Issuer(), "sub": "usr_1", "aud": verifytest.Audience, "jti": "j",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	check(t, p, p.Sign(t, "rt+jwt", verifytest.KeyID, claims), verify.ErrType)
}

func TestAccessTokenRejectsLogoutAndEventTypes(t *testing.T) {
	p := verifytest.NewProvider(t)
	for _, typ := range []string{"logout+jwt", "secevent+jwt"} {
		t.Run(typ, func(t *testing.T) {
			claims := map[string]any{
				"iss": p.Issuer(), "sub": "usr_1", "aud": verifytest.Audience, "jti": "j",
				"exp": time.Now().Add(time.Minute).Unix(), "events": map[string]any{},
			}
			check(t, p, p.Sign(t, typ, verifytest.KeyID, claims), verify.ErrType)
		})
	}
}

func accessClaims(p *verifytest.Provider) map[string]any {
	return map[string]any{
		"iss": p.Issuer(), "sub": "usr_1", "aud": verifytest.Audience, "jti": "j",
		"exp": time.Now().Add(time.Minute).Unix(),
	}
}

func TestAccessTokenRejectsMissingKID(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.Sign(t, "JWT", "", accessClaims(p)), verify.ErrUnknownKey)
}

func TestAccessTokenRejectsUnknownKID(t *testing.T) {
	p := verifytest.NewProvider(t)
	check(t, p, p.Sign(t, "JWT", "forged", accessClaims(p)), verify.ErrUnknownKey)
}

func TestAccessTokenRejectsTamperedSignature(t *testing.T) {
	p := verifytest.NewProvider(t)
	parts := strings.Split(p.AccessToken(t, "usr_1"), ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(payload), "usr_1", "usr_2", 1)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(tampered))
	check(t, p, strings.Join(parts, "."), verify.ErrSignature)
}

func TestAccessTokenRejectsForeignKey(t *testing.T) {
	p := verifytest.NewProvider(t)
	other := verifytest.NewProvider(t)
	check(t, p, other.Sign(t, "JWT", verifytest.KeyID, accessClaims(p)), verify.ErrSignature)
}

func TestTokenRejectsFutureNotBefore(t *testing.T) {
	p := verifytest.NewProvider(t)
	claims := accessClaims(p)
	claims["nbf"] = time.Now().Add(5 * time.Minute).Unix()
	_, err := verify.Token(context.Background(), p.Sign(t, "logout+jwt", verifytest.KeyID, claims), verify.Options{
		Issuer: p.Issuer(), Audience: verifytest.Audience, Keys: p.KeySet(), Leeway: verify.DefaultLeeway, Type: "logout+jwt",
	})
	if !errors.Is(err, verify.ErrNotYetValid) {
		t.Fatalf("got %v, want ErrNotYetValid", err)
	}
}

func TestKeySetUnreachable(t *testing.T) {
	p := verifytest.NewProvider(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	v := verify.NewWithKeySet(p.Issuer(), verifytest.Audience, verify.NewKeySet(url, nil))
	if _, err := v.Verify(context.Background(), p.AccessToken(t, "usr_1")); !errors.Is(err, verify.ErrKeySet) {
		t.Fatalf("got %v, want ErrKeySet", err)
	}
}

func TestOptionsRequireConfiguration(t *testing.T) {
	p := verifytest.NewProvider(t)
	token := p.AccessToken(t, "usr_1")
	for name, opts := range map[string]verify.Options{
		"no issuer":   {Audience: verifytest.Audience, Keys: p.KeySet()},
		"no audience": {Issuer: p.Issuer(), Keys: p.KeySet()},
		"no keys":     {Issuer: p.Issuer(), Audience: verifytest.Audience},
	} {
		if _, err := verify.AccessToken(context.Background(), token, opts); !errors.Is(err, verify.ErrConfig) {
			t.Errorf("%s: got %v, want ErrConfig", name, err)
		}
	}
}

func TestNewDiscoversKeySet(t *testing.T) {
	p := verifytest.NewProvider(t)
	v, err := verify.New(context.Background(), p.Issuer(), verifytest.Audience, verify.WithHTTPClient(p.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v.Issuer() != p.Issuer() || v.Audience() != verifytest.Audience {
		t.Errorf("Issuer %q Audience %q", v.Issuer(), v.Audience())
	}
	if _, err := v.Verify(context.Background(), p.AccessToken(t, "usr_1")); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if n := p.Fetches(); n != 1 {
		t.Errorf("%d key-set fetches, want 1", n)
	}
}

func TestNewRejectsIssuerMismatch(t *testing.T) {
	p := verifytest.NewProvider(t)
	_, err := verify.New(context.Background(), p.Issuer()+"/", verifytest.Audience, verify.WithHTTPClient(p.Client()))
	if !errors.Is(err, verify.ErrIssuer) {
		t.Fatalf("got %v, want ErrIssuer", err)
	}
}

func TestNewRequiresIssuerAndAudience(t *testing.T) {
	ctx := context.Background()
	if _, err := verify.New(ctx, "", "api"); !errors.Is(err, verify.ErrConfig) {
		t.Errorf("no issuer: %v, want ErrConfig", err)
	}
	if _, err := verify.New(ctx, "https://issuer", ""); !errors.Is(err, verify.ErrConfig) {
		t.Errorf("no audience: %v, want ErrConfig", err)
	}
}

func TestWithLeeway(t *testing.T) {
	p := verifytest.NewProvider(t)
	token := p.AccessToken(t, "usr_1", set("exp", time.Now().Add(-90*time.Second).Unix()))
	ctx := context.Background()
	wide := verify.NewWithKeySet(p.Issuer(), verifytest.Audience, p.KeySet(), verify.WithLeeway(2*time.Minute))
	if _, err := wide.Verify(ctx, token); err != nil {
		t.Errorf("with a 2m leeway: %v", err)
	}
	if _, err := p.Verifier().Verify(ctx, token); !errors.Is(err, verify.ErrExpired) {
		t.Errorf("default leeway: %v, want ErrExpired", err)
	}
}
