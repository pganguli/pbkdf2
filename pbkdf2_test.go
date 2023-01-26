package pbkdf2

import (
	"regexp"
	"strings"
	"testing"
)

func TestCreateHash(t *testing.T) {
	hashRX, err := regexp.Compile(`^\$pbkdf2-sha512\$210000\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{86}$`)
	if err != nil {
		t.Fatal(err)
	}

	hash1, err := CreateHash("pa$$word", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	if !hashRX.MatchString(hash1) {
		t.Errorf("hash %q not in correct format", hash1)
	}

	hash2, err := CreateHash("pa$$word", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Compare(hash1, hash2) == 0 {
		t.Error("hashes must be unique")
	}
}

func TestComparePasswordAndHash(t *testing.T) {
	hash, err := CreateHash("pa$$word", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	match, err := ComparePasswordAndHash("pa$$word", hash)
	if err != nil {
		t.Fatal(err)
	}

	if !match {
		t.Error("expected password and hash to match")
	}

	match, err = ComparePasswordAndHash("otherPa$$word", hash)
	if err != nil {
		t.Fatal(err)
	}

	if match {
		t.Error("expected password and hash to not match")
	}
}

func TestDecodeHash(t *testing.T) {
	hash, err := CreateHash("pa$$word", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	params, _, _, err := DecodeHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	if *params != *DefaultParams {
		t.Fatalf("expected %#v got %#v", *DefaultParams, *params)
	}
}

func TestCheckHash(t *testing.T) {
	hash, err := CreateHash("pa$$word", DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	ok, params, err := CheckHash("pa$$word", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("expected password and hash to match")
	}
	if *params != *DefaultParams {
		t.Fatalf("expected %#v got %#v", *DefaultParams, *params)
	}
}

func TestStrictDecoding(t *testing.T) {
	// "bug" valid hash: $pbkdf2-sha512$210000$KuwdBW88vV7YiVGWsMmc8g$XO+ztCemYHheH1kqHe6QAmb99lL3MI7IeBQ05dnAXGk
	ok, _, err := CheckHash("bug", "$pbkdf2-sha512$210000$KuwdBW88vV7YiVGWsMmc8g$XO+ztCemYHheH1kqHe6QAmb99lL3MI7IeBQ05dnAXGk")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("expected password and hash to match")
	}

	// changed one last character of the hash
	ok, _, err = CheckHash("bug", "$pbkdf2-sha512$210000$KuwdBW88vV7YiVGWsMmc8g$XO+ztCemYHheH1kqHe6QAmb99lL3MI7IeBQ05dnAXGl")
	if err == nil {
		t.Fatal("Hash validation should fail")
	}

	if ok {
		t.Fatal("Hash validation should fail")
	}
}

func TestVariant(t *testing.T) {
	// Hash contains wrong variant
	_, _, err := CheckHash("pa$$word", "$pbkdf2-sha256$210000$UDk0zEuIzbt0x3bwkf8Bgw$ihSfHWUJpTgDvNWiojrgcN4E0pJdUVmqCEdRZesx9tE")
	if err != ErrIncompatibleVariant {
		t.Fatalf("Expected error:\n%s\nGot:\n%s", ErrIncompatibleVariant, err)
	}
}
