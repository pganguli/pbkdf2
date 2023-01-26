# PBKDF2-HMAC-SHA512

> **Warning**  
> Key derivation functions requiring constant memory cost such as PBKDF2 and bcrypt are deprecated in favor of those with tunable memory cost, such as scrypt and [argon2](https://github.com/alexedwards/argon2id). Setting a high memory usage for key derivation allows us to thwart hardware (FPGA / ASIC) based attacks.

This package provides a convenience wrapper around Go's [pbkdf2](https://pkg.go.dev/golang.org/x/crypto/pbkdf2?tab=doc) implementation, making it simpler to securely hash and verify passwords using PBKDF2.

It enforces use of the PBKDF2-HMAC-SHA512 algorithm variant and cryptographically-secure random salts.

## Usage

```go
package main

import (
	"log"

	"github.com/pganguli/pbkdf2"
)

func main() {
	// CreateHash returns a PBKDF2-HMAC-SHA512 hash of a plain-text password using the
	// provided algorithm parameters. The returned hash follows the format:
	// $pbkdf2-sha512$210000$yvu2ZftdlhcP4Tbpe2TYqA$XJsU2xkzTyRZur3/+VW07FljLcgKGfmNw+en6y3WJ0JWHHEkn4e46VcaddErsqc9jkJC5IVl4XSlh4lgv0dlug
	hash, err := pbkdf2.CreateHash("pa$$word", pbkdf2.DefaultParams)
	if err != nil {
		log.Fatal(err)
	}

	// ComparePasswordAndHash performs a constant-time comparison between a
	// plain-text password and PBKDF2-HMAC-SHA512 hash, using the parameters and salt
	// contained in the hash. It returns true if they match, otherwise it returns
	// false.
	match, err := pbkdf2.ComparePasswordAndHash("pa$$word", hash)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Match: %v", match)
}
```

### Changing the Parameters

When creating a hash you can and should configure the parameters to be suitable for the environment that the code is running in. The parameters are:

* Iterations — The number of iterations (or passes). 210000 is recommended for PBKDF2-HMAC-SHA512.
* Salt length — Length of the random salt. 16 bytes is recommended for password hashing.
* Key length — Length of the generated key (or password hash). 32 bytes or more is recommended.

The Iterations parameter controls the computational cost of hashing the password. The higher this figure is, the greater the cost of generating the hash and the longer the runtime. It also follows that the greater the cost will be for any attacker trying to guess the password.

```go
params := &pbkdf2.Params{
	Iterations:  210000,
	SaltLength:  16,
	KeyLength:   64,
}


hash, err := pbkdf2.CreateHash("pa$$word", params)
if err != nil {
	log.Fatal(err)
}
```

For guidance and an outline process for choosing appropriate parameters see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2.
