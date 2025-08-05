package rat_test

import (
	"fmt"
	"time"

	"github.com/tetsuo/rat"
)

func ExampleRAT() {
	signingKey := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

	r, err := rat.NewRAT(signingKey)
	if err != nil {
		panic(err)
	}

	secret := []byte("abcdefghijklmnopqrstuvwxABCDEFGHIJKLMNOPQRSTUVWX")                                // 48 bytes
	extra := []byte("abc12")                                                                            // 5 bytes
	refresher := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijABCD") // 76 bytes

	expiry := time.Date(2025, time.August, 7, 0, 30, 27, 0, time.UTC)

	token, err := r.EncodeToString(secret, extra, refresher, expiry)
	if err != nil {
		panic(err)
	}

	fmt.Println("Encoded token length:", len(token))

	decodedSecret, decodedExtra, decodedRefresher, decodedExpiry, err := r.DecodeString(token)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decoded secret:   %s\n", decodedSecret)
	fmt.Printf("Decoded extra:    %s\n", decodedExtra)
	fmt.Printf("Decoded refresher:%s\n", decodedRefresher)
	fmt.Printf("Decoded expiry:   %s\n", decodedExpiry.UTC().Format(time.RFC3339))

	// Output:
	// Encoded token length: 196
	// Decoded secret:   abcdefghijklmnopqrstuvwxABCDEFGHIJKLMNOPQRSTUVWX
	// Decoded extra:    abc12
	// Decoded refresher:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijABCD
	// Decoded expiry:   2025-08-07T00:30:27Z
}
