// Copyright 2012 The Gorilla Authors.
// Portions copyright 2014 Philip Hofer.
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"sync"
	"time"
)

var (
	ErrNoCodecs      = errors.New("securecookie: no codecs provided")
	ErrHashKeyNotSet = errors.New("securecookie: hash key is not set")
	ErrMacInvalid    = errors.New("securecookie: the value is not valid")
	ErrTimeInvalid   = errors.New("securecookie: invalid timestamp")
	ErrNoBlockKey    = errors.New("securecookie: no block key set")
	ErrTooLong       = errors.New("securecookie: value too long")
	ErrExpired       = errors.New("securecookie: expired")
	ErrTooNew        = errors.New("securecookie: timestamp too new")
)

// Codec defines an interface to encode and decode cookie values.
type Codec interface {
	Encode(name string, value interface{}) (string, error)
	Decode(name, value string, dst interface{}) error
}

// Objects passed to Encode and Decode that satisfy
// the Coder interface override the standard gob encoding.
type Coder interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}

// New returns a new SecureCookie.
//
// hashKey is required, used to authenticate values using HMAC. Create it using
// GenerateRandomKey(). It is recommended to use a key with 32 or 64 bytes.
//
// blockKey is optional, used to encrypt values. Create it using
// GenerateRandomKey(). The key length must correspond to the block size
// of the encryption algorithm. For AES, used by default, valid lengths are
// 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func New(hashKey, blockKey []byte) *SecureCookie {
	s := &SecureCookie{
		hashKey:   hashKey,
		blockKey:  blockKey,
		hashFunc:  sha256.New,
		maxAge:    86400 * 30,
		maxLength: 4096,
	}
	s.enc = gob.NewEncoder(&s.buf)
	s.dec = gob.NewDecoder(&s.buf)
	if hashKey == nil {
		s.err = ErrHashKeyNotSet
	}
	if blockKey != nil {
		s.BlockFunc(aes.NewCipher)
	}
	return s
}

// Register registers a type to be used
// with the SecureCookie's internal gob.Encoder and gob.Decoder
// values.
func (s *SecureCookie) Register(v interface{}) error {
	bts, err := serialize(s, v)
	if err != nil {
		return err
	}
	return deserialize(s, bts, v)
}

// SecureCookie encodes and decodes authenticated and optionally encrypted
// cookie values.
type SecureCookie struct {
	hashKey   []byte
	hashFunc  func() hash.Hash
	blockKey  []byte
	block     cipher.Block
	maxLength int
	maxAge    int64
	minAge    int64
	err       error
	lock      sync.Mutex
	buf       bytes.Buffer
	enc       *gob.Encoder
	dec       *gob.Decoder
	// For testing purposes, the function that returns the current timestamp.
	// If not set, it will use time.Now().UTC().Unix().
	timeFunc func() int64
}

// MaxLength restricts the maximum length, in bytes, for the cookie value.
//
// Default is 4096, which is the maximum value accepted by Internet Explorer.
func (s *SecureCookie) MaxLength(value int) *SecureCookie {
	s.maxLength = value
	return s
}

// MaxAge restricts the maximum age, in seconds, for the cookie value.
//
// Default is 86400 * 30. Set it to 0 for no restriction.
func (s *SecureCookie) MaxAge(value int) *SecureCookie {
	s.maxAge = int64(value)
	return s
}

// MinAge restricts the minimum age, in seconds, for the cookie value.
//
// Default is 0 (no restriction).
func (s *SecureCookie) MinAge(value int) *SecureCookie {
	s.minAge = int64(value)
	return s
}

// HashFunc sets the hash function used to create HMAC.
//
// Default is crypto/sha256.New.
func (s *SecureCookie) HashFunc(f func() hash.Hash) *SecureCookie {
	s.hashFunc = f
	return s
}

// BlockFunc sets the encryption function used to create a cipher.Block.
//
// Default is crypto/aes.New.
func (s *SecureCookie) BlockFunc(f func([]byte) (cipher.Block, error)) *SecureCookie {
	if s.blockKey == nil {
		s.err = ErrNoBlockKey
	} else if block, err := f(s.blockKey); err == nil {
		s.block = block
	} else {
		s.err = err
	}
	return s
}

// Encode encodes a cookie value.
//
// It serializes, optionally encrypts, signs with a message authentication code, and
// finally encodes the value.
//
// The name argument is the cookie name. It is stored with the encoded value.
// The value argument is the value to be encoded. It can be any value that can
// be encoded using encoding/gob. To store special structures, they must be
// registered first using gob.Register().
func (s *SecureCookie) Encode(name string, value interface{}) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.hashKey == nil {
		s.err = ErrHashKeyNotSet
		return "", s.err
	}
	var err error
	var b []byte
	// 1. Serialize.
	if enc, ok := value.(Coder); ok {
		b, err = enc.Marshal()
	} else {
		b, err = serialize(s, value)
	}
	if err != nil {
		return "", err
	}
	// 2. Encrypt (optional).
	if s.block != nil {
		if b, err = encrypt(s.block, b); err != nil {
			return "", err
		}
	}
	b = encode(b)
	// 3. Create MAC for "name|date|value". Extra pipe to be used later.
	b = fmtmac(name, s.timestamp(), b)
	mac := createMac(hmac.New(s.hashFunc, s.hashKey), b[:len(b)-1])
	// Append mac, remove name.
	b = append(b, mac...)[len(name)+1:]

	// 4. Encode to base64.
	//b = encode(b)
	out := base64.URLEncoding.EncodeToString(b)

	// 5. Check length.
	if s.maxLength != 0 && len(out) > s.maxLength {
		return "", ErrTooLong
	}
	// Done.
	return out, nil
}

// Decode decodes a cookie value.
//
// It decodes, verifies a message authentication code, optionally decrypts and
// finally deserializes the value.
//
// The name argument is the cookie name. It must be the same name used when
// it was stored. The value argument is the encoded cookie value. The dst
// argument is where the cookie will be decoded. It must be a pointer.
func (s *SecureCookie) Decode(name, value string, dst interface{}) error {
	if s.err != nil {
		return s.err
	}
	if s.hashKey == nil {
		s.err = ErrHashKeyNotSet
		return s.err
	}
	// 1. Check length.
	if s.maxLength != 0 && len(value) > s.maxLength {
		return ErrTooLong
	}
	// 2. Decode from base64.
	b, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	// 3. Verify MAC. Value is "date|value|mac".
	// parts := bytes.SplitN(b, []byte{'|'}, 3)
	parts, err := pipesplit(b)
	if len(parts) != 3 || err != nil {
		return ErrMacInvalid
	}
	h := hmac.New(s.hashFunc, s.hashKey)

	// replicate old MAC
	// prepend "name" and add '|', then append "value" part
	cs := make([]byte, len(name)+len(b)-len(parts[2]))
	nn := copy(cs, name)
	cs[nn] = '|'
	nn += 1
	copy(cs[nn:], b[:len(b)-len(parts[2])-1])

	if err = verifyMac(h, cs, parts[2]); err != nil {
		return err
	}
	// 4. Verify date ranges.
	var t1 int64
	if t1, err = strconv.ParseInt(string(parts[0]), 10, 64); err != nil {
		return ErrTimeInvalid
	}
	t2 := s.timestamp()
	if s.minAge != 0 && t1 > t2-s.minAge {
		return ErrTooNew
	}
	if s.maxAge != 0 && t1 < t2-s.maxAge {
		return ErrExpired
	}
	// 5. Decrypt (optional).
	b, err = decode(parts[1])
	if err != nil {
		return err
	}
	if s.block != nil {
		if b, err = decrypt(s.block, b); err != nil {
			return err
		}
	}
	// 6. Deserialize.
	if dec, ok := dst.(Coder); ok {
		err = dec.Unmarshal(b)
	} else {
		err = deserialize(s, b, dst)
	}
	return err
}

// timestamp returns the current timestamp, in seconds.
//
// For testing purposes, the function that generates the timestamp can be
// overridden. If not set, it will return time.Now().UTC().Unix().
func (s *SecureCookie) timestamp() int64 {
	if s.timeFunc == nil {
		return time.Now().UTC().Unix()
	}
	return s.timeFunc()
}

// Authentication -------------------------------------------------------------

// createMac creates a message authentication code (MAC).
func createMac(h hash.Hash, value []byte) []byte {
	h.Write(value)
	return h.Sum(nil)
}

// verifyMac verifies that a message authentication code (MAC) is valid.
func verifyMac(h hash.Hash, value []byte, mac []byte) error {
	mac2 := createMac(h, value)
	if len(mac) == len(mac2) && subtle.ConstantTimeCompare(mac, mac2) == 1 {
		return nil
	}
	return ErrMacInvalid
}

// Encryption -----------------------------------------------------------------

// encrypt encrypts a value using the given block in counter mode.
//
// A random initialization vector (http://goo.gl/zF67k) with the length of the
// block size is prepended to the resulting ciphertext.
func encrypt(block cipher.Block, value []byte) ([]byte, error) {
	iv := GenerateRandomKey(block.BlockSize())
	if iv == nil {
		return nil, errors.New("securecookie: failed to generate random iv")
	}
	// Encrypt it.
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(value, value)
	// Return iv + ciphertext.
	return append(iv, value...), nil
}

// decrypt decrypts a value using the given block in counter mode.
//
// The value to be decrypted must be prepended by a initialization vector
// (http://goo.gl/zF67k) with the length of the block size.
func decrypt(block cipher.Block, value []byte) ([]byte, error) {
	size := block.BlockSize()
	if len(value) > size {
		// Extract iv.
		iv := value[:size]
		// Extract ciphertext.
		value = value[size:]
		// Decrypt it.
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(value, value)
		return value, nil
	}
	return nil, errors.New("securecookie: the value could not be decrypted")
}

// Serialization --------------------------------------------------------------

// serialize encodes a value using gob.
func serialize(s *SecureCookie, src interface{}) ([]byte, error) {
	s.lock.Lock()
	s.buf.Reset()
	err := s.enc.Encode(src)
	if err != nil {
		s.buf.Reset()
		s.lock.Unlock()
		return nil, err
	}
	out := make([]byte, len(s.buf.Bytes()))
	copy(out, s.buf.Bytes())
	s.lock.Unlock()
	return out, nil
}

// deserialize decodes a value using gob.
func deserialize(s *SecureCookie, src []byte, dst interface{}) error {
	s.lock.Lock()
	s.buf.Reset()
	s.buf.Write(src)
	err := s.dec.Decode(dst)
	s.buf.Reset()
	s.lock.Unlock()
	return err
}

// Encoding -------------------------------------------------------------------

// encode encodes a value using base64.
func encode(value []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(value)))
	base64.URLEncoding.Encode(encoded, value)
	return encoded
}

// decode decodes a cookie using base64.
func decode(value []byte) ([]byte, error) {
	tl := base64.URLEncoding.DecodedLen(len(value))
	if tl <= cap(value) {
		scratch := make([]byte, tl)
		b, err := base64.URLEncoding.Decode(scratch, value)
		if err != nil {
			return nil, err
		}
		copy(value[0:cap(value)], scratch)
		return value[:b], nil
	}
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(value)))
	b, err := base64.URLEncoding.Decode(decoded, value)
	if err != nil {
		return nil, err
	}
	return decoded[:b], nil
}

// split on '|' - find two; return beginning, middle, end
func pipesplit(val []byte) (out [3][]byte, err error) {
	var off int
	for i := 0; i < 2; i++ {
		var loc int
		j := bytes.IndexByte(val[off:], '|')
		// not found (or double pipe...)
		if j == 0 {
			err = ErrMacInvalid
			return
		}
		loc = off + j
		out[i] = val[off:loc]
		off = loc + 1
	}
	out[2] = val[off:]
	return
}

// equivalent to []byte(fmt.Sprintf("%s|%d|%s|", name, s.timestamp(), val))
func fmtmac(name string, time int64, val []byte) []byte {
	tstr := strconv.FormatInt(time, 10)
	tlen := len(name) + len(tstr) + len(val) + 3
	out := make([]byte, tlen)
	var n int
	var nn int
	nn = copy(out[n:], name)
	n += nn
	out[n] = '|'
	n += 1
	nn = copy(out[n:], tstr)
	n += nn
	out[n] = '|'
	n += 1
	nn = copy(out[n:], val)
	n += nn
	out[n] = '|'
	return out
}

// Helpers --------------------------------------------------------------------

// GenerateRandomKey creates a random key with the given strength.
func GenerateRandomKey(strength int) []byte {
	k := make([]byte, strength)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}
	return k
}

// CodecsFromPairs returns a slice of SecureCookie instances.
//
// It is a convenience function to create a list of codecs for key rotation.
func CodecsFromPairs(keyPairs ...[]byte) []Codec {
	codecs := make([]Codec, len(keyPairs)/2+len(keyPairs)%2)
	for i := 0; i < len(keyPairs); i += 2 {
		var blockKey []byte
		if i+1 < len(keyPairs) {
			blockKey = keyPairs[i+1]
		}
		codecs[i/2] = New(keyPairs[i], blockKey)
	}
	return codecs
}

// EncodeMulti encodes a cookie value using a group of codecs.
//
// The codecs are tried in order. Multiple codecs are accepted to allow
// key rotation.
func EncodeMulti(name string, value interface{}, codecs ...Codec) (string, error) {
	if len(codecs) == 0 {
		return "", ErrNoCodecs
	}

	var errors MultiError
	for _, codec := range codecs {
		if encoded, err := codec.Encode(name, value); err == nil {
			return encoded, nil
		} else {
			errors = append(errors, err)
		}
	}
	return "", errors
}

// DecodeMulti decodes a cookie value using a group of codecs.
//
// The codecs are tried in order. Multiple codecs are accepted to allow
// key rotation.
func DecodeMulti(name string, value string, dst interface{}, codecs ...Codec) error {
	if len(codecs) == 0 {
		return ErrNoCodecs
	}

	var errors MultiError
	for _, codec := range codecs {
		if err := codec.Decode(name, value, dst); err == nil {
			return nil
		} else {
			errors = append(errors, err)
		}
	}
	return errors
}

// MultiError groups multiple errors.
type MultiError []error

func (m MultiError) Error() string {
	s, n := "", 0
	for _, e := range m {
		if e != nil {
			if n == 0 {
				s = e.Error()
			}
			n++
		}
	}
	switch n {
	case 0:
		return "(0 errors)"
	case 1:
		return s
	case 2:
		return s + " (and 1 other error)"
	}
	return fmt.Sprintf("%s (and %d other errors)", s, n-1)
}
