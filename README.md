# hpka.js

Browser-compatible implementation of [HPKA](https://github.com/Mowje/hpka).  
Loosely based on [node-hpka](https://github.com/Mowje/node-hpka).  
__NOTE:__ For Ed25519 signatures only!

## Setup

This library is dependent on [libsodium](https://github.com/jedisct1/libsodium). You need to include a [wrapped and emscripten](https://github.com/jedisct1/libsodium.js) compiled version of it.

Prerequisites:
* GNU Build System (that contains `automake` and `libtool`, necessary to compile libsodium)
* emscripten (necessary to compile libsodium to javascript)
* nodejs or io.js (necessary to build the dynamic wrapper for the js build and run tests)

Here's how you should do it:

Once you've got the cloned this repo and installed the dependencies, run
```shell
make
```
That will build libsodium to javascript and build its wrapper `sodium.js`. The files you'd need to import to your app will be located in a `out` folder once the process is finished.

## Usage

Most functions involving "heavy cryptographic calculations" (e.g. : Ed25519 signatures and Scrypt key derviations) __can__ be used asynchronously, but can still be used synchronously.

The library loads in a variable called `hpka`. It exposes the following methods:

* `hpka.supportedAlgorithms()` : Returns a list containing the list of supported algorithms for the identity key. Currently, it only returns `['ed25519']`
* `hpka.createIdentityKey([Buffer|String password], [Function scryptProvider], [Function callback])` : Create an Ed25519 identity key.
    * `String|Buffer password` : Optional. A password used to protected the key (for persistent storage)
    * `Function scryptProvider` : Optional. A function that will perform a Scrypt key derivation and then return it through a callback. Receives ([password, salt, opsLimit, r, p, keyLength], cb), where cb is the callback function that receives (err, derivedKey)
    * `Function callback` : Optional. A function that will receive the result of the `createIdentityKey` call. __Using `callback` is mandatory if `scryptProvider` is provided.__ Received parameters : (err, identityKeyBuffer|encryptedIdentityKeyBuffer)
    * returns an (optionally encrypted) Uint8Array buffer containing the generated key pair
* `hpka.scryptEncrypt(Buffer data, Buffer|String password, [Function scryptProvider], [Function callback])` : Encrypt the provided `data` with the provided `password` and returns the ciphertext. Uses scrypt for key derivation, XSalsa20 as cipher and the Poly1305 MAC
	* `Buffer data` : the data to be encrypted
	* `Buffer|String password` : the password to be derived and used for encryption
    * `Function scryptProvider` : Optional. A function that will perform a Scrypt key derivation and then return it through a callback. Receives ([password, salt, opsLimit, r, p, keyLength], cb), where cb is the callback function that receives (err, derivedKey)
    * `Function callback` : Optional. A function that will receive the result of the `scryptEncrypt` call. __Using `callback` is mandatory if `scryptProvider` is provided.__ Received parameters : (err, cipherText)
	* returns the cipherText (as Uint8Array)
* `hpka.scryptDecrypt(Buffer|String cipher, Buffer|String password, [Function scryptProvider], [Function callback])` : Decrypt the data encrypted by the `scryptEncrypt` method
	* `Buffer|String cipher` : The data to be decrypted. If the provided data is a string, it must be hex encoded.
	* `Buffer|String password` : The password that was used on encryption
    * `Function scryptProvider` : Optional. A function that will perform a Scrypt key derivation and then return it through a callback. Receives ([password, salt, opsLimit, r, p, keyLength], cb), where cb is the callback function that receives (err, derivedKey)
    * `Function callback` : Optional. A function that will receive the result of the `scryptDecrypt` call. __Using `callback` is mandatory if `scryptProvider` is provided.__ Received parameters : (err, plaintext)
	* returns the plaintext (as Uint8Array)
* `hpka.loadKey(Buffer|String keyBuffer, [Buffer|String password], [String resultEncoding], [Function scryptProvider], [Function callback])` : Returns an `{keyType, publicKey, privateKey}` object, where the keys are either Uint8Arrays or strings encoded in `resultEncoding`
* `hpka.saveKey(Object keyPair, [String|Buffer password], [Function scryptProvider], [Function callback])`
* `hpka.buildPayload(Object keyPair, String username, Number userAction, String httpMethod, String hostAndPath)`
* `hpka.buildSessionPayload(String username, String|Uint8Array sessionId)`
* `hpka.Client(String username, Buffer keyBuffer, [Buffer|String password])` : Constructor method for an easy to use HPKA client  
	* String username : the username to be used for the account
	* Buffer keyBuffer : the buffer containing the encoded keypair to be used with this client. KeyBuffer can also be a KeyPair object (resulting form a `hpka.loadKey` call)
	* [Buffer|String password] : Optional. The password to be used to decrypt the keyBuffer. To be used only if the keyBuffer you provided is encrypted  
	#### Instance methods
	__NOTE:__ The `reqOptions` parameter in the `request`, `registerAccount` and `deleteAccount` methods is an object that contains all the parameters needed to make a request. See below for the list of supported attributes and values
	* `hpka.Client.request(reqOptions, callback(err, statusCode, body, headers))` : Make an HPKA authenticated request
	* `hpka.Client.registerAccount(reqOptions, callback(err, statusCode, body, headers))` : Make an HPKA account/user creation request
	* `hpka.Client.deleteAccount(reqOptions, callback(err, statusCode, body, headers))` : Make an HPKA user deletion request
	* `hpka.Client.setHttpAgent(agent)` : Replace the default HTTP agent by one you specify. It should be a function taking the following parameters : reqOptions, callback; where callback will be a function receiving (err, statusCode, responseBody, headers). Example usage : using HPKA in conjunction with [an https client with certificate pinning in Cordova/Phonegap](https://github.com/LockateMe/PinnedHTTPS-Phonegap-Plugin)
	* `hpka.Client.loadKey(Buffer|String keyBuffer, [Buffer|String password])` : Load a keypair into the Client
	* `hpka.Client.keyLoaded()` : Returns whether the client has a keypair loaded in it
	* `hpka.Client.setKeyTtl(Number ttlMilleseconds)` : Set a TTL (time-to-live) for the loaded key, after which it will be unreferenced. Note that the TTL is in milliseconds
	* `hpka.Client.resetKeyTtl(ttl)` : Restart the TTL counter with the current value or with the new `ttl` value
	* `hpka.Client.clearKeyTtl()` : Disable the set TTL
	* `hpka.Client.hasKeyTtl()` : Get whether the client has a TTL set or not
    * `hpka.Client.setSignatureProvider(Function sigProvider)` : Set the Ed25519 provider for this Client instance; a function that will perform the signature and then return it through a callback. That `sigProvider` function receives (message, privateKey, callback), where callback receives (err, signature)
    * `hpka.Client.setScryptProvider(Function scProvider)` : Set the Scrypt provider for this Client instance; a function that will perform the key derivation and then return the result through a callback. That `scProvider` receives ([password, salt, opsLimit, r, p, keyLength], cb), where cb is the callback function that receives (err, derivedKey)
* `hpka.defaultAgent(reqOptions, callback(err, statusCode, body, headers))` : The default HTTP (AJAX) agent used in the `Client` object.

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

From the repo's root folder, run:
```shell
make test
```

This will build the test server's dependencies (if not been previously built) and then launch it. Make sure that the dependencies listed above are installed on your computer. It will then run various test cases in a testing page loaded into phantomjs

## License

This library is distributed under the MIT license.
