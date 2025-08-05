package rat

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"sync"
	"time"
)

type RAT struct {
	hmacPool *sync.Pool
}

func NewRAT(signingKey string) (*RAT, error) {
	b, err := hex.DecodeString(signingKey)
	if err != nil {
		return nil, err
	}
	const minKeySize = 32
	if len(b) < minKeySize {
		return nil, fmt.Errorf("key must be at least 32 bytes")
	}
	return &RAT{
		hmacPool: &sync.Pool{
			New: func() any {
				h := hmac.New(sha256.New, b)
				return h
			},
		},
	}, nil
}

const (
	prefixLen  = 3
	secretLen  = 48
	extraLen   = 5
	payloadLen = extraLen + prefixLen + secretLen + 5
	// max date for storing exp value as 5-bytes varint; safe until year ~2517
	maxUnixVarintTimestamp = 17179869184

	refresherLen = 76 // without ghr_

	tokenLen = payloadLen - prefixLen + sha256.Size // payload without prefix + mac
)

var prefix = []byte("rat") // alphanumeric prefix which would match the cookie name

var (
	ErrInvalidSignature = errors.New("signature not valid")
	ErrCorruptInput     = errors.New("corrupt input")
	ErrValidation       = errors.New("invalid")
)

var (
	tokenEncLen = base64.RawURLEncoding.EncodedLen(tokenLen)

	tokenEncWithRefresherLen = tokenEncLen + refresherLen
)

func encodePayload(b, secret, extra []byte, expiresAt time.Time) error {
	if len(secret) != secretLen {
		return fmt.Errorf("%w: secret length expected %d, got %d", ErrValidation, secretLen, len(secret))
	}
	ttlInHours := math.Ceil(time.Until(expiresAt).Hours())
	if ttlInHours > 400*24 {
		// See https://developer.chrome.com/blog/cookie-max-age-expires
		return fmt.Errorf("%w: session ttl must be less than 400 days (got %.0f hours)", ErrValidation, ttlInHours)
	}
	exp := expiresAt.Unix()
	if exp <= 0 || exp >= maxUnixVarintTimestamp {
		panic("rat: timestamp exceeds the supported date range; fix your system clock")
	}
	if len(extra) != extraLen {
		return fmt.Errorf("%w: extra length expected %d, got %d", ErrValidation, extraLen, len(extra))
	}
	if !isAlphanum(extra) {
		return fmt.Errorf("%w: extra must be ASCII alphanumeric", ErrValidation)
	}
	// exp
	n := binary.PutVarint(b[prefixLen:], exp)
	// secret
	n += copy(b[prefixLen+n:], secret[:secretLen])
	// extra data
	copy(b[prefixLen+n:], extra[:extraLen])
	// name
	copy(b, prefix)
	return nil
}

// EncodeToString builds and signs an auth token.
// Final token = base64(payload-without-prefix | mac) + refresherASCII
func (c *RAT) EncodeToString(secret, extra, refresher []byte, expiresAt time.Time) (string, error) {
	if len(refresher) != refresherLen {
		return "", fmt.Errorf("%w: refresh token length expected %d, got %d", ErrValidation, refresherLen, len(refresher))
	}
	if !isAlphanum(refresher) {
		return "", fmt.Errorf("%w: refresh token must be ASCII alphanumeric", ErrValidation)
	}

	// payload (incl. prefix)
	var payload [payloadLen]byte
	if err := encodePayload(payload[:], secret, extra, expiresAt); err != nil {
		return "", err
	}

	// mac: prefix + (payload w/o prefix) + refresher
	mac := c.hmacPool.Get().(hash.Hash)
	mac.Reset()
	if _, err := mac.Write(prefix); err != nil { // keep prefix in the signature
		return "", err
	}
	if _, err := mac.Write(payload[prefixLen:]); err != nil {
		return "", err
	}
	if _, err := mac.Write(refresher); err != nil {
		return "", err
	}
	var digest [sha256.Size]byte
	_ = mac.Sum(digest[:0])
	c.hmacPool.Put(mac)

	var token [tokenLen]byte
	copy(token[:payloadLen-prefixLen], payload[prefixLen:])
	copy(token[payloadLen-prefixLen:], digest[:])

	out := make([]byte, tokenEncWithRefresherLen)
	base64.RawURLEncoding.Encode(out[:tokenEncLen], token[:])
	copy(out[tokenEncLen:], refresher)

	return string(out), nil
}

// DecodeString verifies and parses a token produced by EncodeToString.
func (c *RAT) DecodeString(token string) ([]byte, []byte, []byte, time.Time, error) {
	if len(token) != tokenEncWithRefresherLen {
		return nil, nil, nil, time.Time{}, fmt.Errorf("%w: invalid token length, expected %d, got %d",
			ErrCorruptInput, tokenEncWithRefresherLen, len(token))
	}

	encPart := token[:len(token)-refresherLen]

	// base64-decode payload(w/o prefix)|mac
	buf, err := base64.RawURLEncoding.DecodeString(encPart)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("%w: %v", ErrCorruptInput, err)
	}
	if len(buf) != tokenLen {
		return nil, nil, nil, time.Time{}, fmt.Errorf("%w: invalid input length, expected %d, got %d",
			ErrCorruptInput, tokenLen, len(buf))
	}

	payloadPart := buf[:payloadLen-prefixLen] // starts with varint, no "rat"
	macPart := buf[payloadLen-prefixLen:]

	// verify MAC (prefix + payloadPart + refresher)
	mac := c.hmacPool.Get().(hash.Hash)
	mac.Reset()
	if _, err := mac.Write(prefix); err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	if _, err := mac.Write(payloadPart); err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	refresher := []byte(token[len(token)-refresherLen:])
	if _, err := mac.Write(refresher); err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	var sum [sha256.Size]byte
	_ = mac.Sum(sum[:0])
	c.hmacPool.Put(mac)
	if !hmac.Equal(macPart, sum[:]) {
		return nil, nil, nil, time.Time{}, ErrInvalidSignature
	}

	// parse payloadPart
	exp, n := binary.Varint(payloadPart)
	if exp <= 0 || exp >= maxUnixVarintTimestamp {
		return nil, nil, nil, time.Time{}, fmt.Errorf("%w: timestamp exceeds the supported date range",
			ErrValidation)
	}
	expiresAt := time.Unix(exp, 0)

	secret := payloadPart[n : n+secretLen]
	extra := payloadPart[n+secretLen : n+secretLen+extraLen]

	return secret, extra, refresher, expiresAt, nil
}

func isAlphanum(b []byte) bool {
	for _, c := range b {
		if !(c >= 'A' && c <= 'Z' ||
			c >= 'a' && c <= 'z' ||
			c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
