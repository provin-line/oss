// Package jwtprincipal resolves the principal a bearer JWT stands for. It is
// the authentication step of the cedar PDP backend: a Cedar agent decides for
// whatever principal it is given and authenticates nothing, so the token is
// verified here before the agent is asked.
//
// A token is accepted only when its signature verifies against the configured
// key, it carries an expiry that has not passed, it is not used before its
// not-before time, its issuer equals the configured issuer, its audience
// contains the configured audience, and it has a subject. The principal is
// that subject. Everything else is refused; there is no partial acceptance.
package jwtprincipal

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	// leeway is the clock skew tolerated between the token issuer and this
	// node when checking exp and nbf.
	leeway = 30 * time.Second

	// minSecretBytes is the shortest accepted HS256 key after decoding
	// (RFC 7518 §3.2: at least the hash output size).
	minSecretBytes = 32
)

// Encodings of Config.Secret.
const (
	EncodingUTF8   = "utf8"
	EncodingHex    = "hex"
	EncodingBase64 = "base64"
)

// Resolver authenticates a bearer token and names its principal. An error means
// the token is refused; the error text is for logs and never reaches the RPC
// caller.
type Resolver interface {
	Principal(ctx context.Context, token string) (string, error)
}

// Config selects how bearer tokens are verified. Exactly one of JWKSURL and
// Secret is set.
type Config struct {
	// Issuer is the required value of the iss claim.
	Issuer string
	// Audience must be one of the values of the aud claim.
	Audience string
	// JWKSURL is the https URL of the issuer's key set (asymmetric algorithms).
	JWKSURL string
	// Secret is the shared HS256 key, written in SecretEncoding.
	Secret string
	// SecretEncoding is utf8, hex or base64. Empty means utf8. It applies to
	// Secret only.
	SecretEncoding string
}

// New validates cfg and returns the Resolver for its key source.
func New(cfg Config) (Resolver, error) {
	return newResolver(cfg, nil, time.Now)
}

func newResolver(cfg Config, client keyFetchClient, now func() time.Time) (Resolver, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("issuer must not be empty")
	}
	if cfg.Audience == "" {
		return nil, errors.New("audience must not be empty")
	}
	switch {
	case cfg.JWKSURL != "" && cfg.Secret != "":
		return nil, errors.New("set exactly one of jwks-url and secret, not both")
	case cfg.JWKSURL == "" && cfg.Secret == "":
		return nil, errors.New("set exactly one of jwks-url and secret")
	}
	v := &verifier{issuer: cfg.Issuer, audience: cfg.Audience, now: now}
	if cfg.JWKSURL != "" {
		if cfg.SecretEncoding != "" {
			return nil, errors.New("secret-encoding applies to secret only")
		}
		if err := validateJWKSURL(cfg.JWKSURL); err != nil {
			return nil, fmt.Errorf("jwks-url: %w", err)
		}
		v.algs = asymmetricAlgs
		v.keys = newJWKSCache(cfg.JWKSURL, client, now)
		return v, nil
	}
	secret, err := decodeSecret(cfg.Secret, cfg.SecretEncoding)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	v.algs = []jose.SignatureAlgorithm{jose.HS256}
	v.keys = staticKey(secret)
	return v, nil
}

func validateJWKSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("must be an https:// URL")
	}
	if u.Host == "" {
		return errors.New("must have a host")
	}
	if u.User != nil {
		return errors.New("must not embed userinfo credentials")
	}
	return nil
}

func decodeSecret(s, encoding string) ([]byte, error) {
	var (
		b   []byte
		err error
	)
	switch encoding {
	case "", EncodingUTF8:
		b = []byte(s)
	case EncodingHex:
		b, err = hex.DecodeString(s)
	case EncodingBase64:
		b, err = base64.StdEncoding.DecodeString(s)
	default:
		return nil, fmt.Errorf("unknown secret-encoding %q (want utf8|hex|base64)", encoding)
	}
	if err != nil {
		// The decoder's error is not wrapped: it can quote bytes of the secret.
		return nil, fmt.Errorf("not valid %s", encoding)
	}
	if len(b) < minSecretBytes {
		return nil, fmt.Errorf("must be at least %d bytes after decoding (got %d)", minSecretBytes, len(b))
	}
	return b, nil
}

// asymmetricAlgs is the set of signature algorithms accepted from a JWKS. It
// excludes HMAC (a public key must never act as an HMAC secret) and none.
var asymmetricAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// keySource yields the verification key for a token's header.
type keySource interface {
	key(ctx context.Context, h jose.Header) (any, error)
}

type staticKey []byte

func (k staticKey) key(context.Context, jose.Header) (any, error) { return []byte(k), nil }

type verifier struct {
	issuer, audience string
	algs             []jose.SignatureAlgorithm
	keys             keySource
	now              func() time.Time
}

func (v *verifier) Principal(ctx context.Context, token string) (string, error) {
	tok, err := jwt.ParseSigned(token, v.algs)
	if err != nil {
		return "", fmt.Errorf("parse token: %w", err)
	}
	if len(tok.Headers) != 1 {
		return "", errors.New("token must carry exactly one signature")
	}
	key, err := v.keys.key(ctx, tok.Headers[0])
	if err != nil {
		return "", err
	}
	var claims jwt.Claims
	if err := tok.Claims(key, &claims); err != nil {
		return "", fmt.Errorf("verify signature: %w", err)
	}
	if claims.Expiry == nil {
		return "", errors.New("token has no exp claim")
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      v.issuer,
		AnyAudience: jwt.Audience{v.audience},
		Time:        v.now(),
	}, leeway)
	if err != nil {
		return "", fmt.Errorf("validate claims: %w", err)
	}
	if claims.Subject == "" {
		return "", errors.New("token has no sub claim")
	}
	return claims.Subject, nil
}
