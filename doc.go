// Copyright 2012 The Gorilla Authors. All rights reserved.
// Portions copyright 2014 Philip Hofer.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package gorilla/securecookie encodes and decodes authenticated and optionally
encrypted cookie values.

Secure cookies can't be forged, because their values are validated using HMAC.
When encrypted, the content is also inaccessible to malicious eyes.

To use it, first create a new SecureCookie instance:

	var hashKey = []byte("very-secret")
	var blockKey = []byte("a-lot-secret")
	var s = securecookie.New(hashKey, blockKey)

The hashKey is required, used to authenticate the cookie value using HMAC.
It is recommended to use a key with 32 or 64 bytes.

The blockKey is optional, used to encrypt the cookie value -- set it to nil
to not use encryption. If set, the length must correspond to the block size
of the encryption algorithm. For AES, used by default, valid lengths are
16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.

Strong keys can be created using the convenience function GenerateRandomKey().

Before using custom values with a cookie, they must be registered:

	type MyType struct{
		Foo int
		Bar string
	}

	s.Register(&MyType{})

Once a SecureCookie instance is set, use it to encode a cookie value:

	func SetCookieHandler(w http.ResponseWriter, r *http.Request) {
		value := MyType{
			Foo: 42,
			Bar: "bar",
		}
		if encoded, err := s.Encode("cookie-name", value); err == nil {
			cookie := &http.Cookie{
				Name:  "cookie-name",
				Value: encoded,
				Path:  "/",
			}
			http.SetCookie(w, cookie)
		}
	}

Later, use the same SecureCookie instance to decode and validate a cookie
value:

	func ReadCookieHandler(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("cookie-name"); err == nil {
			value := &MyType{}
			if err = s2.Decode("cookie-name", cookie.Value, value); err == nil {
				fmt.Fprintf(w, "The value of foo is %q", value["foo"])
			}
		}
	}

We stored a map[string]string, but secure cookies can hold any value that
can be encoded using encoding/gob. To store custom types, they must be
registered first using cookie.Register(<value>).
*/
package securecookie
