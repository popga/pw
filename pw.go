package pw

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params struct used for hashing
type Params struct {
	time       uint32
	memory     uint32
	threads    uint8
	keyLength  uint32
	saltLength uint32
}

// GenerateHash generates a new hash and returns params, salt, hash, err
func GenerateHash(password string) (*Params, []byte, []byte, error) {
	params := &Params{
		time:       1,
		memory:     64 * 1024,
		threads:    4,
		keyLength:  32,
		saltLength: 16,
	}
	salt, err := GenerateRandomBytes(params.saltLength)
	if err != nil {
		return nil, nil, nil, err
	}
	return params, salt, argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, params.keyLength), nil
}

// GenerateHashBase64 returns a base64 encoded hash and an error
func GenerateHashBase64(password string) (string, error) {
	p, salt, hash, err := GenerateHash(password)
	if err != nil {
		return "", err
	}
	saltBase64 := base64.RawStdEncoding.EncodeToString(salt)
	hashBase64 := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.memory, p.time, p.threads, saltBase64, hashBase64), nil
}

// DecodeHash decodes the given encoded hash and returns params, salt, hash, err
func DecodeHash(encodedHash string) (*Params, []byte, []byte, error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid hash")
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("incompatible version")
	}

	params := &Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &params.memory, &params.time, &params.threads)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.saltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	params.keyLength = uint32(len(hash))

	return params, salt, hash, nil
}

// ComparePasswordAndHash compares the given password string with the given encoded hash string
func ComparePasswordAndHash(password, encodedHash string) (bool, error) {
	p, salt, hash, err := DecodeHash(encodedHash)
	if err != nil {
		return false, err
	}
	otherHash := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, p.keyLength)
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}
