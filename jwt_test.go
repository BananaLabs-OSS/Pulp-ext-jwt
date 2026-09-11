package jwtext

import (
	"context"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tetratelabs/wazero"
)

func TestConfiguredRejectsShortOrBlankSecrets(t *testing.T) {
	if configured("") || configured("too-short") {
		t.Fatal("weak host key was accepted")
	}
	if !configured("0123456789abcdef0123456789abcdef") {
		t.Fatal("valid host key was rejected")
	}
}

func TestCapabilityRegistrationAndBinders(t *testing.T) {
	var capability *ext.Capability
	for _, candidate := range ext.All() {
		if candidate.Name == Capability {
			candidate := candidate
			capability = &candidate
			break
		}
	}
	if capability == nil {
		t.Fatal("identity.jwt.hs256 is not registered")
	}
	if capability.Provider != Provider || capability.Register == nil || capability.Stub == nil {
		t.Fatalf("invalid capability registration: %#v", capability)
	}
	for name, binder := range map[string]func(wazero.HostModuleBuilder, ext.Cell) error{
		"active": capability.Register,
		"stub":   capability.Stub,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			runtime := wazero.NewRuntime(ctx)
			t.Cleanup(func() { _ = runtime.Close(ctx) })
			builder := runtime.NewHostModuleBuilder("env")
			if err := binder(builder, nil); err != nil {
				t.Fatal(err)
			}
			module, err := builder.Instantiate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, export := range []string{"jwt_sign", "jwt_verify"} {
				if module.ExportedFunctionDefinitions()[export] == nil {
					t.Fatalf("missing %s export", export)
				}
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(1_800_000_000, 0)
	encoded, err := sign(secret, signRequest{AccountID: "account-1", SessionID: "session-1", ExpiresAt: now.Add(time.Minute).UnixMilli()}, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verify(secret, encoded, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccountID != "account-1" || got.SessionID != "session-1" {
		t.Fatalf("unexpected claims: %#v", got)
	}
	if _, err := verify([]byte("abcdef0123456789abcdef0123456789"), encoded, now); err == nil {
		t.Fatal("token verified with the wrong secret")
	}
	if _, err := verify(secret, encoded, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired token verified")
	}
}

func TestVerifyRequiresExpirationAndHS256(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(1_800_000_000, 0)
	withoutExpiry, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{AccountID: "a", SessionID: "s"}).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(secret, withoutExpiry, now); err == nil {
		t.Fatal("token without expiration verified")
	}
	none := jwt.NewWithClaims(jwt.SigningMethodNone, claims{RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))}, AccountID: "a", SessionID: "s"})
	unsigned, err := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(secret, unsigned, now); err == nil {
		t.Fatal("non-HS256 token verified")
	}
}

func TestVerifyRejectsTamperingAndCrossProtocolClaims(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(1_800_000_000, 0)
	encoded, err := sign(secret, signRequest{AccountID: "a", SessionID: "s", ExpiresAt: now.Add(time.Minute).UnixMilli()}, now)
	if err != nil {
		t.Fatal(err)
	}
	tampered := encoded[:len(encoded)-1] + "x"
	if _, err := verify(secret, tampered, now); err == nil {
		t.Fatal("tampered token verified")
	}
	wrongAudience := claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: Provider, Audience: jwt.ClaimStrings{"another.protocol"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))},
		AccountID:        "a", SessionID: "s",
	}
	crossProtocol, err := jwt.NewWithClaims(jwt.SigningMethodHS256, wrongAudience).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(secret, crossProtocol, now); err == nil {
		t.Fatal("token for another audience verified")
	}
}

func TestSignRejectsShortSecretAndNonFutureExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	req := signRequest{AccountID: "a", SessionID: "s", ExpiresAt: now.Add(time.Minute).UnixMilli()}
	if _, err := sign([]byte("short"), req, now); err == nil {
		t.Fatal("short secret signed a token")
	}
	req.ExpiresAt = now.UnixMilli()
	if _, err := sign([]byte("0123456789abcdef0123456789abcdef"), req, now); err == nil {
		t.Fatal("non-future expiry was accepted")
	}
}
