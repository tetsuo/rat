# RAT 🐀

Refreshable Auth Token (RAT) is a compact, URL-safe token format for authentication use.

# RAT/1

```go
base64url(payload | signature) + refresher
```

where:

- `payload`: fixed-length binary-encoded data
- `signature`: HMAC-SHA256 of selected fields
- `refresher`: a raw ASCII string

### Prefix

* 3 bytes: ASCII string `"rat"`
* Included in signatures

### Expiration timestamp

* 1–5 bytes: signed varint-encoded Unix timestamp
* Must be within a valid range: `0 < exp < 17179869184` (like year 2517)

### Secret

* 48 bytes
* Opaque binary value, application-defined

### Extra

* 5 bytes
* Must be ASCII alphanumeric (`[A-Za-z0-9]`)
* Application-defined use

### Refresh token

* 76 bytes
* Must be ASCII alphanumeric
* Appended to the base64-encoded payload

### Signature

* 32 bytes (HMAC-SHA256)
* Computed over:

  ```go
  input := prefix + payload + refresher
  signature = HMAC-SHA256(key, input)
  ```

#### Final RAT size:

- Base64-encoded part: 120 characters
- Full token length: 120 + 76 = 196 characters

## Decoding and validation

To decode and validate a RAT:

1. Separate the encoded portion and the refresher
2. Base64-decode the payload and signature
3. Recompute the MAC and verify signature
4. Extract:
   * Expiration via `binary.Varint`
   * Secret (next 48 bytes)
   * Extra (next 5 bytes)
5. Reject if:
   * Any field has invalid length or characters
   * Timestamp is zero, expired, or out of range
   * Signature does not match
