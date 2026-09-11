// Package jwtext provides host-owned JWT signing and verification.
//
// The signing key is read only from PULP_JWT_HS256_SECRET. It is never part
// of a cell manifest, guest request, or guest response.
package jwtext

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/vmihailenco/msgpack/v5"
)

const Capability = "identity.jwt.hs256"
const unavailable uint32 = 99

const Provider = "github.com/BananaLabs-OSS/Pulp-ext-jwt"

type signRequest struct {
	AccountID string `msgpack:"account_id"`
	SessionID string `msgpack:"session_id"`
	ExpiresAt int64  `msgpack:"expires_at"`
}
type verifyRequest struct {
	Token string `msgpack:"token"`
}
type claims struct {
	jwt.RegisteredClaims
	AccountID string `json:"account_id"`
	SessionID string `json:"session_id"`
}
type verifyResponse struct {
	AccountID string `msgpack:"account_id"`
	SessionID string `msgpack:"session_id"`
}

func init() {
	ext.Register(ext.Capability{Name: Capability, Provider: Provider, Register: func(b wazero.HostModuleBuilder, _ ext.Cell) error {
		bind(b, []byte(os.Getenv("PULP_JWT_HS256_SECRET")))
		return nil
	}, Stub: bindStub})
}

func bind(b wazero.HostModuleBuilder, secret []byte) {
	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, p, n, op, on uint32) uint32 {
		if len(secret) < 32 {
			return unavailable
		}
		data, ok := m.Memory().Read(p, n)
		if !ok || n == 0 {
			return 2
		}
		var req signRequest
		if msgpack.Unmarshal(data, &req) != nil || req.AccountID == "" || req.SessionID == "" || req.ExpiresAt <= time.Now().UnixMilli() {
			return 3
		}
		token, err := sign(secret, req, time.Now())
		if err != nil {
			return 4
		}
		return write(ctx, m, map[string]string{"token": token}, op, on)
	}).Export("jwt_sign")
	b.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, p, n, op, on uint32) uint32 {
		if len(secret) < 32 {
			return unavailable
		}
		data, ok := m.Memory().Read(p, n)
		if !ok || n == 0 {
			return 2
		}
		var req verifyRequest
		if msgpack.Unmarshal(data, &req) != nil || req.Token == "" {
			return 3
		}
		parsed, err := verify(secret, req.Token, time.Now())
		if err != nil {
			return 5
		}
		return write(ctx, m, parsed, op, on)
	}).Export("jwt_verify")
}

func sign(secret []byte, req signRequest, now time.Time) (string, error) {
	if len(secret) < 32 {
		return "", errors.New("HS256 secret must be at least 32 bytes")
	}
	if req.AccountID == "" || req.SessionID == "" || req.ExpiresAt <= now.UnixMilli() {
		return "", errors.New("invalid claims")
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Provider,
			Audience:  jwt.ClaimStrings{Capability},
			ExpiresAt: jwt.NewNumericDate(time.UnixMilli(req.ExpiresAt)),
		},
		AccountID: req.AccountID,
		SessionID: req.SessionID,
	}).SignedString(secret)
}

func verify(secret []byte, encoded string, now time.Time) (verifyResponse, error) {
	if len(secret) < 32 {
		return verifyResponse{}, errors.New("HS256 secret must be at least 32 bytes")
	}
	var parsed claims
	token, err := jwt.ParseWithClaims(encoded, &parsed, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	}, jwt.WithTimeFunc(func() time.Time { return now }), jwt.WithExpirationRequired(), jwt.WithIssuer(Provider), jwt.WithAudience(Capability))
	if err != nil || token == nil || !token.Valid || parsed.AccountID == "" || parsed.SessionID == "" {
		return verifyResponse{}, errors.New("invalid token")
	}
	return verifyResponse{AccountID: parsed.AccountID, SessionID: parsed.SessionID}, nil
}

func bindStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	for _, name := range []string{"jwt_sign", "jwt_verify"} {
		b.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32) uint32 { return unavailable }).Export(name)
	}
	return nil
}
func write(ctx context.Context, m api.Module, v any, op, on uint32) uint32 {
	data, err := msgpack.Marshal(v)
	if err != nil {
		return 6
	}
	f := m.ExportedFunction("pulp_alloc")
	if f == nil {
		return 7
	}
	result, err := f.Call(ctx, uint64(len(data)))
	if err != nil || len(result) == 0 || result[0] == 0 {
		return 7
	}
	p := uint32(result[0])
	if !m.Memory().Write(p, data) || !m.Memory().WriteUint32Le(op, p) || !m.Memory().WriteUint32Le(on, uint32(len(data))) {
		return 8
	}
	return 0
}

// configured is deliberately retained for focused host tests without reading
// a real environment secret.
func configured(secret string) bool { return len(secret) >= 32 }
