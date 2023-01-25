// Package pbkdf2 provides a convience wrapper around Go's golang.org/x/crypto/pbkdf2
// implementation, making it simpler to securely hash and verify passwords
// using PBKDF2.
//
// It enforces use of the PBKDF2-HMAC-SHA512 algorithm variant and cryptographically-secure
// random salts.
package pbkdf2

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

var (
	// ErrInvalidHash in returned by ComparePasswordAndHash if the provided
	// hash isn't in the expected format.
	ErrInvalidHash = errors.New("pbkdf2: hash is not in the correct format")

	// ErrIncompatibleVariant is returned by ComparePasswordAndHash if the
	// provided hash was created using a unsupported variant of PBKDF2.
	// Currently only PBKDF2-HMAC-SHA512 is supported by this package.
	ErrIncompatibleVariant = errors.New("pbkdf2: incompatible variant of pbkdf2")
)

// DefaultParams provides some sane default parameters for hashing passwords.
//
// Follows recommendations given by the NIST.
//
// The default parameters should generally be used for development/testing purposes
// only. Custom parameters should be set for production applications depending on
// available memory/CPU resources and business requirements.
var DefaultParams = &Params{
	Iterations: 210000,
	SaltLength: 16,
	KeyLength:  32,
}

// Params describes the input parameters used by the PBKDF2 algorithm. The
// Iterations parameter controls the computational cost of hashing
// the password. The higher this figure is, the greater the cost of generating
// the hash and the longer the runtime. It also follows that the greater the cost
// will be for any attacker trying to guess the password. Important note:
// Changing the value of the Iterations parameter changes the hash output.
//
// For guidance and an outline process for choosing appropriate parameters see
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
type Params struct {
	// The number of iterations.
	Iterations uint32

	// Length of the random salt. 16 bytes is recommended for password hashing.
	SaltLength uint32

	// Length of the generated key. 16 bytes or more is recommended.
	KeyLength uint32
}

// CreateHash returns a PBKDF2-HMAC-SHA512 hash of a plain-text password using the
// provided algorithm parameters. The returned hash follows the format:
//
//	$pbkdf2-sha512${Iterations}${b64Salt}${b64Key}
//
// It looks like this:
//
//	$pbkdf2-sha512$210000$KuwdBW88vV7YiVGWsMmc8g$XO+ztCemYHheH1kqHe6QAmb99lL3MI7IeBQ05dnAXGk
func CreateHash(password string, params *Params) (hash string, err error) {
	salt, err := generateRandomBytes(params.SaltLength)
	if err != nil {
		return "", err
	}

	key := pbkdf2.Key([]byte(password), salt, int(params.Iterations), int(params.KeyLength), sha512.New)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	hash = fmt.Sprintf("$pbkdf2-sha512$%d$%s$%s", params.Iterations, b64Salt, b64Key)
	return hash, nil
}

// ComparePasswordAndHash performs a constant-time comparison between a
// plain-text password and PBKDF2-HMAC-SHA512 hash, using the parameters and salt
// contained in the hash. It returns true if they match, otherwise it returns
// false.
func ComparePasswordAndHash(password, hash string) (match bool, err error) {
	match, _, err = CheckHash(password, hash)
	return match, err
}

// CheckHash is like ComparePasswordAndHash, except it also returns the params that the hash was
// created with. This can be useful if you want to update your hash params over time (which you
// should).
func CheckHash(password, hash string) (match bool, params *Params, err error) {
	params, salt, key, err := DecodeHash(hash)
	if err != nil {
		return false, nil, err
	}

	otherKey := pbkdf2.Key([]byte(password), salt, int(params.Iterations), int(params.KeyLength), sha512.New)

	keyLen := int32(len(key))
	otherKeyLen := int32(len(otherKey))

	if subtle.ConstantTimeEq(keyLen, otherKeyLen) == 0 {
		return false, params, nil
	}
	if subtle.ConstantTimeCompare(key, otherKey) == 1 {
		return true, params, nil
	}
	return false, params, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeHash expects a hash created from this package, and parses it to return the params used to
// create it, as well as the salt and key (password hash).
func DecodeHash(hash string) (params *Params, salt, key []byte, err error) {
	vals := strings.Split(hash, "$")
	if len(vals) != 5 {
		return nil, nil, nil, ErrInvalidHash
	}

	if vals[1] != "pbkdf2-sha512" {
		return nil, nil, nil, ErrIncompatibleVariant
	}

	params = &Params{}
	_, err = fmt.Sscanf(vals[2], "%d", &params.Iterations)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[3])
	if err != nil {
		return nil, nil, nil, err
	}
	params.SaltLength = uint32(len(salt))

	key, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.KeyLength = uint32(len(key))

	return params, salt, key, nil
}
