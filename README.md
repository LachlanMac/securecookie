securecookie 2
============

[![Build Status](https://travis-ci.org/philhofer/securecookie.svg)](https://travis-ci.org/philhofer/securecookie)

This is a fork of [gorilla/securecookie](http://github.com/gorilla/securecookie) that addresses a non-trivial performance issue:

|   Implementation       |  time/op  | mem/op   | allocs/op | 
| ---------------------- |:---------:|:--------:|:---------:|
| gorilla/securecookie   | 75,275 ns | 21,396 B |    369    |
| philhofer/securecookie | 17,483 ns | 3,198 B  |     33    |
|       *delta*          |   -76.7%  |  -85.0%  |   -91.0%  |


The difference in performance comes from avoiding the re-allocation of the `gob.Encoder` and `gob.Decoder` types. In order to accomodate this change, a backwards-incompatible change had to be made to the API: all used types need to be `Register()`ed with a new cookie in order for it to properly handle gob-encoded values from other cookies. The previous implementation may not be able to decode 
cookies created by the new implementation, but this implementation is still able to decode "old" cookies.

### Documentation

Full documentation at [godoc](http://godoc.org/github.com/philhofer/securecookie).