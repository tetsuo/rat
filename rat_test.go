package rat_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tetsuo/rat"
)

var (
	testSecret    = bytes.Repeat([]byte("abc123"), 8) // 48 bytes
	testExtra     = []byte("hello")                   // 5 bytes
	testRefresher = bytes.Repeat([]byte("r"), 76)
	testExpiresAt = time.Now().Add(24 * time.Hour)
)

var testSignKey []byte

func init() {
	signKey, err := hex.DecodeString("ca16ed3b8030fffdf9cedb500785e885f0fe2bcd5fe66eb485c91e46394b8a33")
	if err != nil {
		panic(err)
	}
	testSignKey = signKey
}

var codec *rat.RAT

func TestMain(m *testing.M) {
	var err error
	codec, err = rat.NewRAT(hex.EncodeToString(testSignKey))
	if err != nil {
		panic(err)
	}
	code := m.Run()
	os.Exit(code)
}

func TestEncode_ValidationErrors(t *testing.T) {
	validSecret := testSecret
	validExtra := testExtra
	validRefresher := testRefresher
	validExpiresAt := testExpiresAt

	t.Run("invalid refresher length", func(t *testing.T) {
		_, err := codec.EncodeToString(validSecret, validExtra, []byte("short"), validExpiresAt)
		if err == nil || err.Error() != "invalid: refresh token length expected 76, got 5" {
			t.Errorf("expected invalid refresher length error, got: %v", err)
		}
	})

	t.Run("non-alphanumeric refresher", func(t *testing.T) {
		badRefresher := bytes.Repeat([]byte("r"), 75)
		badRefresher = append(badRefresher, '#')
		_, err := codec.EncodeToString(validSecret, validExtra, badRefresher, validExpiresAt)
		if err == nil || err.Error() != "invalid: refresh token must be ASCII alphanumeric" {
			t.Errorf("expected non-alphanumeric refresher error, got: %v", err)
		}
	})

	t.Run("invalid secret length", func(t *testing.T) {
		badSecret := bytes.Repeat([]byte("a"), 20)
		_, err := codec.EncodeToString(badSecret, validExtra, validRefresher, validExpiresAt)
		if err == nil || err.Error() == "" || err.Error()[:8] != "invalid:" {
			t.Errorf("expected invalid secret length error, got: %v", err)
		}
	})

	t.Run("invalid extra length", func(t *testing.T) {
		badExtra := []byte("toolong")
		_, err := codec.EncodeToString(validSecret, badExtra, validRefresher, validExpiresAt)
		if err == nil || err.Error() == "" || err.Error()[:8] != "invalid:" {
			t.Errorf("expected invalid extra length error, got: %v", err)
		}
	})

	t.Run("non-alphanumeric extra", func(t *testing.T) {
		badExtra := []byte("hel$o")
		_, err := codec.EncodeToString(validSecret, badExtra, validRefresher, validExpiresAt)
		if err == nil || err.Error() != "invalid: extra must be ASCII alphanumeric" {
			t.Errorf("expected non-alphanumeric extra error, got: %v", err)
		}
	})

	t.Run("ttl too long", func(t *testing.T) {
		longTTL := time.Now().Add(401 * 24 * time.Hour)
		_, err := codec.EncodeToString(validSecret, validExtra, validRefresher, longTTL)
		if err == nil || err.Error() == "" || err.Error()[:8] != "invalid:" {
			t.Errorf("expected TTL too long error, got: %v", err)
		}
	})
}

func TestDecode_Failures(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		// refresher is ignored here, base64 part is malformed
		_, _, _, _, err := codec.DecodeString("!!!notbase64!!!" + string(testRefresher))
		if err == nil || !errors.Is(err, rat.ErrCorruptInput) {
			t.Fatalf("expected ErrCorruptInput, got: %v", err)
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		token, err := codec.EncodeToString(testSecret, testExtra, testRefresher, testExpiresAt)
		if err != nil {
			t.Fatalf("Encode failed: %v", err)
		}

		enc := token[:len(token)-76]
		shortEnc := enc[:len(enc)-5] // truncate
		shortToken := shortEnc + string(testRefresher)

		_, _, _, _, err = codec.DecodeString(shortToken)
		if err == nil || !errors.Is(err, rat.ErrCorruptInput) {
			t.Fatalf("expected ErrCorruptInput for short token, got: %v", err)
		}
	})

	t.Run("invalid hmac", func(t *testing.T) {
		token, err := codec.EncodeToString(testSecret, testExtra, testRefresher, testExpiresAt)
		if err != nil {
			t.Fatalf("Encode failed: %v", err)
		}

		enc := token[:len(token)-76]
		raw, _ := base64.RawURLEncoding.DecodeString(enc)
		raw[10] ^= 0xFF
		tampered := base64.RawURLEncoding.EncodeToString(raw) + string(testRefresher)

		_, _, _, _, err = codec.DecodeString(tampered)
		if err == nil || !errors.Is(err, rat.ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got: %v", err)
		}
	})

	const prefixLen = 3
	const secretLen = 48
	const extraLen = 5
	const payloadLen = prefixLen + 5 + secretLen + extraLen

	t.Run("bad varint encoding", func(t *testing.T) {
		token, err := codec.EncodeToString(testSecret, testExtra, testRefresher, testExpiresAt)
		if err != nil {
			t.Fatalf("Encode failed: %v", err)
		}

		enc := token[:len(token)-76]
		ref := token[len(token)-76:]

		raw, _ := base64.RawURLEncoding.DecodeString(enc)

		// corrupt the varint
		raw[3] = 0x80
		raw[4] = 0x80
		raw[5] = 0x80
		raw[6] = 0x80
		raw[7] = 0x80
		raw[8] = 0x02

		// recompute HMAC: "rat" + payloadPart (58 B) + refresher
		payloadPart := raw[:payloadLen-prefixLen] // 58-byte slice
		mac := hmac.New(sha256.New, testSignKey)
		mac.Write([]byte("rat"))
		mac.Write(payloadPart)
		mac.Write([]byte(ref))
		copy(raw[payloadLen-prefixLen:], mac.Sum(nil)) // write digest back

		// re-assemble tampered token
		tampered := base64.RawURLEncoding.EncodeToString(raw) + ref
		_, _, _, _, err = codec.DecodeString(tampered)
		if err == nil || !errors.Is(err, rat.ErrValidation) {
			t.Fatalf("expected ErrValidation due to varint corruption, got: %v", err)
		}
	})

}

func TestEncode_Success(t *testing.T) {
	token, err := codec.EncodeToString(testSecret, testExtra, testRefresher, testExpiresAt)
	if err != nil {
		t.Fatalf("expected Encode to succeed, got error: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token string")
	}

	if !strings.HasSuffix(token, string(testRefresher)) {
		t.Error("expected token to end with refresher")
	}

	if strings.Contains(token[:len(token)-76], string(testRefresher[:4])) {
		t.Error("refresher should not be encoded into base64 portion")
	}
}

func TestDecode_Success(t *testing.T) {
	token, err := codec.EncodeToString(testSecret, testExtra, testRefresher, testExpiresAt)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	secret, extra, refresher, expiresAt, err := codec.DecodeString(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !bytes.Equal(secret, testSecret) {
		t.Error("decoded secret does not match original")
	}
	if !bytes.Equal(extra, testExtra) {
		t.Error("decoded extra does not match original")
	}
	if !bytes.Equal(refresher, testRefresher) {
		t.Error("decoded refresher does not match original")
	}

	delta := expiresAt.Sub(testExpiresAt)
	if delta < -2*time.Second || delta > 2*time.Second {
		t.Errorf("decoded expiresAt mismatch: expected %v, got %v", testExpiresAt, expiresAt)
	}
}
