# hpka.js

Browser-compatible implementation of [HPKA](https://github.com/Mowje/hpka).  
Loosely based on [node-hpka](https://github.com/Mowje/node-hpka).  
__NOTE:__ For Ed25519 signatures only!

## Setup

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

## Usage

The library loads in a variable called `hpka`. It exposes the following methods:

* `hpka.supportedAlgorithms()` : Returns a list containing the list of supported algorithms for the identity key. Currently, it only returns `['ed25519']`
* `hpka.createIdentityKey([Buffer|String password])` : Create an Ed25519 identity key.
 	* String|Buffer password : Optional. A password used to protected the key (for persistent storage)
	* returns an (optionally encrypted) Uint8Array buffer containing the generated key pair
* `hpka.scryptEncrypt(Buffer data, Buffer|String password)` : Encrypt the provided `data` with the provided `password` and returns the ciphertext. Uses scrypt for key derivation, XSalsa20 as cipher and the Poly1305 MAC
	* Buffer data : the data to be encrypted
	* Buffer|String password : the password to be dervied and used for encryption
	* returns the ciphertext (as Uint8Array)
* `hpka.scryptDecrypt(Buffer|String cipher, Buffer|String password)` : Decrypt the data encrypted by the `scryptEncrypt` method
	* Buffer|String cipher : The data to be decrypted. If the provided data is a string, it must be hex encoded.
	* Buffer|String password : The password that was used on encryption
	* returns the plaintext (as Uint8Array)
* `hpka.loadKey(Buffer|String keyBuffer, [Buffer|String password])`
* `hpka.saveKey(Object keyPair, [String|Buffer password])`
* `hpka.buildPayload(Object keyPair, String username, Number userAction, String httpMethod, String hostAndPath)`
* `hpka.Client(String username, Buffer keyBuffer, [Buffer|String password])` : Constructor method for an easy to use HPKA client  
	* String username : the username to be used for the account
	* Buffer keyBuffer : the buffer containing the encoded keypair to be used with this client
	* [Buffer|String password] : Optional. The password to be used to decrypt the keyBuffer. To be used only if the keyBuffer you provided is encrypted  
	#### Instance methods
	__NOTE: __ The `reqOptions` parameter in the `request`, `registerAccount` and `deleteAccount` methods is an object that contains all the parameters needed to make a request. See below for the list of supported attributes and values
	* `hpka.Client.request(reqOptions, callback(err, statusCode, body))` : Make an HPKA authenticated request
	* `hpka.Client.registerAccount(reqOptions, callback(err, statusCode, body))` : Make an HPKA account/user creation request
	* `hpka.Client.deleteAccount(reqOptions, callback(err, statusCode, body))` : Make an HPKA user deletion request
	* `hpka.Client.setHttpAgent(agent)` : Replace the default HTTP agent by one you specify. It should be a function taking the following parameters : reqOptions, callback; where callback will be a function receiving (err, statusCode, responseBody). Example usage : using HPKA in conjunction with [an https client with certificate pinning in Cordova/Phonegap](https://github.com/LockateMe/PinnedHTTPS-Phonegap-Plugin)
	* `hpka.Client.loadKey(Buffer|String keyBuffer, [Buffer|String password])` : Load a keypair into the Client
	* `hpka.Client.keyLoaded()` : Returns whether the client has a keypair loaded in it
	* `hpka.Client.setKeyTtl(Number ttlMilleseconds)` : Set a TTL (time-to-live) for the loaded key, after which it will be unreferenced. Note that the TTL is in milliseconds
	* `hpka.Client.resetKeyTtl()` : Restart the TTL counter with the current value
	* `hpka.Client.clearKeyTtl()` : Disable the set TTL
	* `hpka.Client.hasKeyTtl()` : Get whether the client has a TTL set or not
* `hpka.defaultAgent(reqOptions, callback)` : The default HTTP (AJAX) agent used in the `Client` object.

### `reqOptions`

Here are the list of attributes taken in the `reqOptions` object:
* String host : the hostname to which you want to connect
* String path : the path of your request. Must start with a `/`
* String method : the HTTP method you want to use. Valid values are: `get`, `post`, `put`, `delete`, `head`, `patch`, `trace`, `options`, `connect`
* [Number port] : The port number you want to use. Optional parameter. Defaults to 443 (the port for HTTPS)
* [String protocol] : The protocol you want to use. Optional parameter. Must either be 'http' or 'https'. Defaults to 'https'
* [Object headers] : The headers you want to include in your requests. Optional parameter
* [String|Object body] : The request body you want to include. Optional parameter

## Test

An automated testing page was written (`test/test.html`). To launch the tests :

* Go to the `test` directory
* Run `npm install` to install the server's dependencies
* Add the libsodium files, as you would normally do. (As described in the setup paragraph above)
* Run `node server.js`, then head your browser to `http://localhost:2500/test.html`, then click on the "Test" button

## License

This library is distributed under the MIT license.
