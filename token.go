package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// newUUIDv7 creates an RFC 9562 UUIDv7 using the system CSPRNG.
func newUUIDv7() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate UUIDv7 entropy: %w", err)
	}

	ms := uint64(time.Now().UnixMilli())
	id[0] = byte(ms >> 40)
	id[1] = byte(ms >> 32)
	id[2] = byte(ms >> 24)
	id[3] = byte(ms >> 16)
	id[4] = byte(ms >> 8)
	id[5] = byte(ms)
	id[6] = (id[6] & 0x0f) | 0x70
	id[8] = (id[8] & 0x3f) | 0x80

	var raw [32]byte
	hex.Encode(raw[:], id[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", raw[0:8], raw[8:12], raw[12:16], raw[16:20], raw[20:32]), nil
}

func isUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := make([]byte, 0, 32)
	for i := range value {
		if value[i] != '-' {
			compact = append(compact, value[i])
		}
	}
	decoded := make([]byte, 16)
	if _, err := hex.Decode(decoded, compact); err != nil {
		return false
	}
	return decoded[6]>>4 == 7 && decoded[8]&0xc0 == 0x80
}

func validateToken(token string) error {
	if !isUUIDv7(token) {
		return errors.New("token must be an RFC 9562 UUIDv7")
	}
	return nil
}
