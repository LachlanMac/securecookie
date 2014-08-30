// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var testCookies = []interface{}{
	map[string]string{"foo": "bar"},
	map[string]string{"baz": "ding"},
}

var testStrings = []string{"foo", "bar", "baz"}

func TestSecureCookie(t *testing.T) {
	// TODO test too old / too new timestamps

	s1 := New([]byte("12345"), []byte("1234567890123456"))
	s2 := New([]byte("54321"), []byte("6543210987654321"))
	value := map[string]interface{}{
		"foo": "bar",
		"baz": 128,
	}

	for i := 0; i < 50; i++ {
		// Running this multiple times to check if any special character
		// breaks encoding/decoding.
		encoded, err1 := s1.Encode("sid", value)
		if err1 != nil {
			t.Error(err1)
			continue
		}
		dst := make(map[string]interface{})
		err2 := s1.Decode("sid", encoded, &dst)
		if err2 != nil {
			t.Fatalf("%v: %v", err2, encoded)
		}
		// check map equality
		for key, val := range value {
			v, ok := dst[key]
			if !ok || !reflect.DeepEqual(v, val) {
				t.Fatalf("%v and %v not equal", v, val)
			}
		}

		dst2 := make(map[string]interface{})
		err3 := s2.Decode("sid", encoded, &dst2)
		if err3 == nil {
			t.Fatalf("Expected failure decoding.")
		}
	}
}

func TestAuthentication(t *testing.T) {
	hash := hmac.New(sha256.New, []byte("secret-key"))
	for _, value := range testStrings {
		hash.Reset()
		signed := createMac(hash, []byte(value))
		hash.Reset()
		err := verifyMac(hash, []byte(value), signed)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestEncryption(t *testing.T) {
	block, err := aes.NewCipher([]byte("1234567890123456"))
	if err != nil {
		t.Fatalf("Block could not be created")
	}
	var encrypted, decrypted []byte
	for _, value := range testStrings {
		if encrypted, err = encrypt(block, []byte(value)); err != nil {
			t.Error(err)
		} else {
			if decrypted, err = decrypt(block, encrypted); err != nil {
				t.Error(err)
			}
			if string(decrypted) != value {
				t.Errorf("Expected %v, got %v.", value, string(decrypted))
			}
		}
	}
}

func TestSerialization(t *testing.T) {
	var (
		serialized   []byte
		deserialized map[string]string
		err          error
	)
	s := New([]byte("12345"), []byte("1234567890123456"))
	for _, value := range testCookies {
		if serialized, err = serialize(s, value); err != nil {
			t.Error(err)
		} else {
			deserialized = make(map[string]string)
			if err = deserialize(s, serialized, &deserialized); err != nil {
				t.Error(err)
			}
			if fmt.Sprintf("%v", deserialized) != fmt.Sprintf("%v", value) {
				t.Errorf("Expected %v, got %v.", value, deserialized)
			}
		}
	}
}

func TestFmtMac(t *testing.T) {
	tests := []struct {
		Name string
		Time int64
		Val  []byte
	}{
		{"blah", 14093290, []byte("garbage")},
	}

	for _, ts := range tests {
		got := string(fmtmac(ts.Name, ts.Time, ts.Val))
		want := fmt.Sprintf("%s|%d|%s|", ts.Name, ts.Time, ts.Val)
		if got != want {
			t.Errorf("Got %q; wanted %q", got, want)
		}
	}
}

func TestPipesplit(t *testing.T) {
	tests := []struct {
		In  string
		Out [3][]byte
	}{
		{"a|b|c", [3][]byte{[]byte("a"), []byte("b"), []byte("c")}},
		{"a_thing|another_thing here!|blah blah blah", [3][]byte{[]byte("a_thing"), []byte("another_thing here!"), []byte("blah blah blah")}},
	}

	for _, test := range tests {
		got, err := pipesplit([]byte(test.In))
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(got, test.Out) {
			t.Errorf("Wanted %v; got %v", test.Out, got)
		}
	}
}

func TestEncoding(t *testing.T) {
	for _, value := range testStrings {
		encoded := encode([]byte(value))
		decoded, err := decode(encoded)
		if err != nil {
			t.Error(err)
		} else if string(decoded) != value {
			t.Errorf("Expected %v, got %s.", value, string(decoded))
		}
	}
}

func TestMultiError(t *testing.T) {
	s1, s2 := New(nil, nil), New(nil, nil)
	_, err := EncodeMulti("sid", "value", s1, s2)
	if len(err.(MultiError)) != 2 {
		t.Errorf("Expected 2 errors, got %s.", err)
	} else {
		if strings.Index(err.Error(), "hash key is not set") == -1 {
			t.Errorf("Expected missing hash key error, got %s.", err.Error())
		}
	}
}

func TestMultiNoCodecs(t *testing.T) {
	_, err := EncodeMulti("foo", "bar")
	if err != errNoCodecs {
		t.Errorf("EncodeMulti: bad value for error, got: %v", err)
	}

	var dst []byte
	err = DecodeMulti("foo", "bar", &dst)
	if err != errNoCodecs {
		t.Errorf("DecodeMulti: bad value for error, got: %v", err)
	}
}

// ----------------------------------------------------------------------------

type FooBar struct {
	Foo int
	Bar string
}

func TestCustomType(t *testing.T) {
	s1 := New([]byte("12345"), []byte("1234567890123456"))
	// Type is not registered in gob. (!!!)
	src := &FooBar{42, "bar"}
	encoded, _ := s1.Encode("sid", src)

	dst := &FooBar{}
	_ = s1.Decode("sid", encoded, dst)
	if dst.Foo != 42 || dst.Bar != "bar" {
		t.Fatalf("Expected %#v, got %#v", src, dst)
	}
}

func TestDifferentCookies(t *testing.T) {
	one := New([]byte("12345"), []byte("1234567890123456"))
	two := New([]byte("12345"), []byte("1234567890123456"))

	src := &FooBar{42, "bar"}
	err := one.Register(src)
	if err != nil {
		t.Fatal(err)
	}
	err = two.Register(src)
	if err != nil {
		t.Fatal(err)
	}

	// register other garbage with both
	// so we're sure that they don't have to
	// share any other properties
	two.Register(int(3))
	two.Register("hello there")
	one.Register(map[string]string{})

	val, err := one.Encode("sid", src)
	if err != nil {
		t.Fatal(err)
	}

	// then do it again; make sure it's not "self-describing"
	val, err = one.Encode("sid", src)
	if err != nil {
		t.Fatal(err)
	}

	dst := &FooBar{}
	err = two.Decode("sid", val, dst)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(dst, src) {
		t.Fatal("not equal")
	}
}

func BenchmarkRoundtrip(b *testing.B) {
	cook := New([]byte("12345"), []byte("1234567890123456"))

	src := &FooBar{42, "bar"}
	cook.Register(src)

	b.ResetTimer()
	b.ReportAllocs()
	var err error
	var val string
	for i := 0; i < b.N; i++ {
		val, err = cook.Encode("sid", src)
		if err != nil {
			b.Fatal(err)
		}
		err = cook.Decode("sid", val, src)
		if err != nil {
			b.Fatal(err)
		}
	}
}
