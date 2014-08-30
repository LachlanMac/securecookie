securecookie
============

This is a fork of [gorilla/securecookie](http://github.com/gorilla/securecookie) that addresses a non-trivial performance issue.

|   Implementation       |  time/op  | mem/op   | allocs/op | 
| ---------------------- |:---------:|:--------:|:---------:|
| gorilla/securecookie   | 75,275 ns | 21,396 B |    369    |
| philhofer/securecookie | 17,483 ns | 3,198 B  |     33    |


The difference in performance comes from avoiding the re-allocation of the `gob.Encoder` and `gob.Decoder` types. In order to accomodate this change, a backwards-incompatible change had to be made to the API: all used types need to be `Register()`ed with a new cookie in order for it to properly handle gob-encoded values from other cookies. Cookies will not be able to properly decode types that have not been registered.