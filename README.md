# hpka.js

Browser-compatible implementation of [HPKA](https://github.com/Mowje/hpka).  
Loosely based on [node-hpka](https://github.com/Mowje/node-hpka).  
__NOTE:__ For Ed25519 signatures only!

## Usage

This library is dependent on [libsodium](https://github.com/jedisct1/libsodium). You need to include a [wrapped and emscripten](https://github.com/LockateMe/libsodium) compiled version of it.

Prerequisites:
* autotools (necessary to compile libsodium)
* emscripten (necessary to compile libsodium to javascript)
* nodejs (necessary to build the dynamic wrapper for the js build and run tests)

Here's how you should do it:

1. Once you've got the hpka.js file, clone the libsodium fork containing the WIP wrapper.
```
git clone https://github.com/LockateMe/libsodium.git
```
2. `cd` to the clone and run `./autogen.sh`
3. Then, run from the same folder `./dist-build/emscripten.sh`. It will compile libsodium to javascript and run some tests. Note that the tests will be slow, and that out of the 56 tests 2 will fail.
4. The generated files are in `./libsodium-js/lib/`. Copy the following files to your app:
	* libsodium.js
	* libsodium.js.mem
	* libsodium.js.symbols
	* libsodium-wrap.js

## Test

This library hasn't been tested yet. A blank & dumb server will be implemented (inspired probably from [this one](https://github.com/Mowje/node-hpka/blob/master/test.js))

## License

This library is distributed under the MIT license.
