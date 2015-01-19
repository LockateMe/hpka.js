/*
* HPKA in-browser client
* Written by Ahmad Ben Mrad
* Distributed under the MIT license
* See https://github.com/LockateMe/hpka.js for more info
*/
var hpka = (function(){
	var lib = {};

	//if (!libsodium) throw new Error('libsodium is missing!');
	if (!sodium) throw new Error('The libsodium wrapper (sodium.js) is missing')

	var is_hex = sodium.is_hex;
	var from_hex = sodium.from_hex;
	var to_hex = sodium.to_hex;
	var from_base64 = sodium.from_base64;
	var to_base64 = sodium.to_base64;

	function supportedAlgorithms(){return ['ed25519'];}

	function getVerbId(verb){
		if (typeof verb != 'string') throw new TypeError('verb must be a string');
		verb = verb.toLowerCase();
		if (verb == 'get') return 0x01;
		else if (verb == 'post') return 0x02;
		else if (verb == 'put') return 0x03;
		else if (verb == 'delete') return 0x04;
		else if (verb == 'head') return 0x05;
		else if (verb == 'trace') return 0x06;
		else if (verb == 'options') return 0x07;
		else if (verb == 'connect') return 0x08;
		else if (verb == 'patch') return 0x09;
		else return undefined;
	}

	function getVerbFromId(verbID){
		if (typeof verbID != 'number') throw new TypeError('verbID must be a number');
		if (verbID == 0x01) return 'get';
		else if (verbID == 0x02) return 'post';
		else if (verbID == 0x03) return 'put';
		else if (verbID == 0x04) return 'delete';
		else if (verbID == 0x05) return 'head';
		else if (verbID == 0x06) return 'trace';
		else if (verbID == 0x07) return 'options';
		else if (verbID == 0x08) return 'connect';
		else if (verbID == 0x09) return 'patch';
		else return undefined;
	}

	function client(username, keyBuffer, password){
		if (typeof username != 'string') throw new TypeError('username must be a string');
		if (!(keyBuffer && keyBuffer instanceof Uint8Array)) throw new TypeError('keyBuffer must be a Uint8Array');
		if (password && !(typeof password == 'string' || password instanceof Uint8Array)) throw new TypeError('passowrd must be a Uint8Array');

		var httpAgent = defaultAgent;
		var _username, _password, _keyPair, _keyTtl, _keyClearTimeout;
		_username = username;
		_keyPair = loadKey(keyBuffer, password);

		this.request = function(reqOptions, callback){
			doHpkaReq(0x00, reqOptions, callback);
		};

		this.registerAccount = function(reqOptions, callback){
			doHpkaReq(0x01, reqOptions, callback);
		};

		this.deleteAccount = function(reqOptions, callback){
			doHpkaReq(0x02, reqOptions, callback);
		};

		this.setHttpAgent = function(agent){
			if (typeof agent != 'function') throw new TypeError('agent must be a function');
			httpAgent = agent;
		};

		this.setKeyTtl = function(ttl){
			if (!(typeof ttl == 'number' && ttl > 0 && Math.floor(ttl) == ttl)) throw new TypeError('ttl must be a strictly positive integer');
			_keyTtl = ttl;
			_keyClearTimeout = setTimeout(ttlEndHandler, _keyTtl);
		};

		this.resetKeyTtl = function(){
			if (!(_keyClearTimeout && _keyTtl)) return;
			clearTimeout(_keyClearTimeout);
			_keyClearTimeout = setTimeout(ttlEndHandler, _keyTtl);
		};

		this.clearKeyTtl = function(){
			if (!_keyClearTimeout) return;
			clearTimeout(_keyClearTimeout);
			_keyClearTimeout = null;
		};

		this.hasKeyTtl = function(){
			return !!_keyClearTimeout;
		};

		this.loadKey = function(keyBuffer, password){
			_keyPair = loadKey(keyBuffer, password);
		};

		this.keyLoaded = function(){
			return !!_keyPair;
		};

		function ttlEndHandler(){
			//In case the original buffer was protected by password, remove references to it
			_keyClearTimeout = null;
			if (_keyPair.privateKey) delete _keyPair.privateKey;
			if (_keyPair.publicKey) delete _keyPair.publicKey;
			if (_keyPair.keyType) delete _keyPair.keyType;
			if (_keyPair) _keyPair = null;
		}

		function hostAndPath(reqOptions){
			return reqOptions.host + reqOptions.path;
		}

		function doHpkaReq(actionCode, reqOptions, callback){
			if (!(typeof actionCode == 'number' && Math.floor(actionCode) == actionCode && actionCode >= 0x00 && actionCode <= 0x04)) throw new TypeError('Invalid actionCode');
			if (typeof reqOptions != 'object') throw new TypeError('reqOptions must be an object');
			if (typeof callback != 'function') throw new TypeError('callback must be a function');
			validateReqOptions(reqOptions);

			var hpkaPayload = hpka.buildPayload(_keyPair, _username, actionCode, reqOptions.method, hostAndPath(reqOptions));
			if (!reqOptions.headers) reqOptions.headers = {};
			reqOptions.headers['HPKA-Req'] = hpkaPayload.req;
			reqOptions.headers['HPKA-Signature'] = hpkaPayload.sig;
			httpAgent(reqOptions, callback);
		}
	}

	/*
	* reqOptions: {host, port, path, method, headers, body, protocol}
	* callback: (err, statusCode, body)
	*/
	function defaultAgent(reqOptions, callback){
		if (typeof reqOptions != 'object') throw new TypeError('reqOptions must be an object');
		if (typeof callback != 'function') throw new TypeError('callback must be a function');

		validateReqOptions(reqOptions);

		var xhReq = new XMLHttpRequest();
		var reqUrl = reqOptions.protocol + '://' + reqOptions.host + ':' + reqOptions.port.toString() + reqOptions.path;
		xhReq.open(reqOptions.method, reqUrl, true);
		xhReq.onload = function(){
			callback(null, xhReq.status, xhReq.responseText);
		};
		xhReq.onerror = function(e){
			callback(e);
		};
		xhReq.onabort = function(e){
			callback(e);
		}

		if (reqOptions.headers){
			var headersNames = Object.keys(reqOptions.headers);
			for (var i = 0; i < headersNames.length; i++) xhReq.setRequestHeader(headersNames[i], reqOptions.headers[headersNames[i]]);
		}

		if (reqOptions.body){
			var bodyStr;
			if (typeof reqOptions.body == 'object'){
				xhReq.setRequestHeader('Content-Type', 'appplication/json');
				try {
					bodyStr = JSON.stringify(reqOptions.body);
				} catch (e){
					throw new Error('Cannot stringify body object. Please check for circular references');
					return;
				}
			} else bodyStr = reqOptions.body;
			xhReq.send(bodyStr);
		} else xhReq.send();
	}

	function validateReqOptions(reqOptions){
		if (typeof reqOptions != 'object') throw new TypeError('reqOptions must be an object');
		reqOptions.path = reqOptions.path || '/';
		reqOptions.port = Number(reqOptions.port) || 443;
		reqOptions.protocol = reqOptions.protocol || 'https';
		reqOptions.method = reqOptions.method || 'get';

		if (typeof reqOptions.host != 'string') throw new TypeError('reqOptions.host must be a defined string');
		if (typeof reqOptions.path != 'string') throw new TypeError('reqOptions.path must be a string');
		if (reqOptions.path.indexOf('/') != 0) throw new TypeError('reqOptions.path must start with a /');
		if (reqOptions.headers && typeof reqOptions.headers != 'object') throw new TypeError('when defined, reqOptions.headers must be an object');
		if (!(typeof reqOptions.method == 'string' && getVerbId(reqOptions.method))) throw new TypeError('reqOptions.method must be a string and a valid HTTP method');
		if (!(typeof reqOptions.port == 'number' && !isNaN(reqOptions.port) && Math.floor(reqOptions.port) == reqOptions.port && reqOptions.port > 0 && reqOptions.port < 65536)) throw new TypeError('reqOptions.port must be a positive integer between 0 and 65536');
		if (!(typeof reqOptions.protocol == 'string' && (reqOptions.protocol == 'http' || reqOptions.protocol == 'https'))) throw new TypeError('Protocol must either be "http" or "https"');
		if (reqOptions.body && !(typeof reqOptions.body == 'object' || typeof reqOptions.body == 'string')) throw new TypeError('when defined, reqOptions.body must either an object or a string');
	}

	function createKey(password){
		if (password && !(password instanceof Uint8Array || typeof password == 'string')) throw new TypeError('When defined, password must either be a string or a Uint8Array');
		var ed25519Seed = randomBuffer(sodium.crypto_sign_seedbytes);
		var ed25519KeyPair = sodium.crypto_sign_seed_keypair(ed25519Seed);

		if (password){
			var keyBuffer = keyEncode(ed25519KeyPair, 'ed25519');
			var encryptedKeyBuffer = scryptEncrypt(keyBuffer, password);
			var finalBuf = new Uint8Array(encryptedKeyBuffer.length + 1); //Adding one byte at the beginng, for keyType
			finalBuf[0] = 0x06;
			for (var i = 0; i < encryptedKeyBuffer.length; i++){
				finalBuf[i+1] = encryptedKeyBuffer[i];
			}
			return finalBuf;
			//throw new Error('Key generation with password not implemented yet');
		} else return keyEncode(ed25519KeyPair, 'ed25519');
	}

	function changeKeyPassword(keyBuffer, currentPassword, newPassword){

	}

	function keyEncode(keyPair, keyType){
		if (typeof keyPair != 'object') throw new TypeError('keyPair must be an object');
		if (!(keyPair.publicKey && (keyPair.privateKey || keyPair.secretKey))) throw new TypeError('keyPair must contain public and private keys');
		keyType = keyPair.keyType || keyType;
		if (typeof keyType != 'string') throw new TypeError('keyType must be a string');
		if (!(keyType == 'ed25519' || keyType == 'curve25519')) throw new TypeError('key must either be ed25519 or curve25519');

		//Decode hex if provided in hex
		var decodedKeyPair = {};
		var publicKeyParam = keyPair.publicKey;
		if (is_hex(publicKeyParam)){
			decodedKeyPair.publicKey = from_hex(publicKeyParam);
		} else if (publicKeyParam instanceof Uint8Array){
			decodedKeyPair.publicKey = publicKeyParam;
		} else throw new TypeError('Invalid public key format. Must either be a Uint8Array or a hex-string');

		var privateKeyParam = keyPair.privateKey || keyPair.secretKey;
		if (is_hex(privateKeyParam)){
			decodedKeyPair.privateKey = from_hex(privateKeyParam);
		} else if (privateKeyParam instanceof Uint8Array){
			decodedKeyPair.privateKey = privateKeyParam;
		} else throw new TypeError('Invalid private key format. Must either be a Uint8Array or a hex-string');

		if (keyType == 'ed25519'){
			if (decodedKeyPair.publicKey.length != sodium.crypto_sign_publickeybytes) throw new Error('Ed25519 public key must be ' + sodium.crypto_sign_publickeybytes + ' bytes long, and not ' + decodedKeyPair.publicKey.length);
			if (decodedKeyPair.privateKey.length != sodium.crypto_sign_secretkeybytes) throw new Error('Ed25519 private key must be ' + sodium.crypto_sign_secretkeybytes + ' bytes long, and not ' + decodedKeyPair.privateKey.length);
		} else {
			if (decodedKeyPair.publicKey.length != sodium.crypto_box_publickeybytes) throw new Error('Curve25519 public key must be ' + sodium.crypto_box_publickeybytes + ' bytes long, and not ' + decodedKeyPair.publicKey.length);
			if (decodedKeyPair.privateKey.length != sodium.crypto_box_secretkeybytes) throw new Error('Curve25519 private key must be' + sodium.crypto_box_secretkeybytes + ' bytes long, and not ' + decodedKeyPair.privateKey.length);
		}

		// 5 = 1 byte for keyType + 2 bytes for sk length + 2 bytes for pk length
		var curve25519EncSize = 5 + sodium.crypto_box_secretkeybytes + sodium.crypto_box_publickeybytes;
		var ed25519EncSize = 5 + sodium.crypto_sign_secretkeybytes + sodium.crypto_sign_publickeybytes;

		var encodedB = new Uint8Array(keyType == 'ed25519' ? ed25519EncSize : curve25519EncSize);
		//Writing keyType byte
		var bufIndex = 1;
		encodedB[0] = (keyType == 'curve25519' ? 0x05 : 0x06);
		if (keyType == 'curve25519'){
			//Writing public key size
			encodedB[bufIndex] = sodium.crypto_box_publickeybytes >> 8;
			encodedB[bufIndex+1] = sodium.crypto_box_publickeybytes;
			bufIndex += 2;
			//Writing public key
			for (var i = 0; i < decodedKeyPair.publicKey.length; i++){
				encodedB[bufIndex + i] = decodedKeyPair.publicKey[i];
			}
			bufIndex += decodedKeyPair.publicKey.length;
			//Writing secret key size
			encodedB[bufIndex] = sodium.crypto_box_secretkeybytes >> 8;
			encodedB[bufIndex+1] = sodium.crypto_box_secretkeybytes;
			bufIndex += 2;
			//Writing secret key
			for (var i = 0; i < decodedKeyPair.privateKey.length; i++){
				encodedB[bufIndex+i] = decodedKeyPair.privateKey[i];
			}
			bufIndex += decodedKeyPair.privateKey.length;
		} else { //Ed25519
			//Writing public key size
			encodedB[bufIndex] = sodium.crypto_sign_publickeybytes >> 8;
			encodedB[bufIndex+1] = sodium.crypto_sign_publickeybytes;
			bufIndex += 2;
			//Writing public key
			for (var i = 0; i < decodedKeyPair.publicKey.length; i++){
				encodedB[bufIndex+i] = decodedKeyPair.publicKey[i];
			}
			bufIndex += decodedKeyPair.publicKey.length;
			//Writing secret key size
			encodedB[bufIndex] = sodium.crypto_sign_secretkeybytes >> 8;
			encodedB[bufIndex+1] = sodium.crypto_sign_secretkeybytes;
			bufIndex += 2;
			//Writing secret key
			for (var i = 0; i < decodedKeyPair.privateKey.length; i++){
				encodedB[bufIndex+i] = decodedKeyPair.privateKey[i];
			}
			bufIndex += decodedKeyPair.privateKey.length;
		}

		return encodedB;
	}

	function keyDecode(encodedKeyPair){
		if (!(encodedKeyPair && (encodedKeyPair instanceof Uint8Array || typeof encodedKeyPair == 'string'))) throw new TypeError('Parameter encoded key pair must either be a Uint8Array or a string');
		if (typeof encodedKeyPair == 'string' && !is_hex(encodedKeyPair)) throw new TypeError('When encodedKeyPair is a string, it must be hex encoded');

		var enc;
		if (typeof encodedKeyPair == 'string') enc = from_hex(encodedKeyPair);
		else enc = encodedKeyPair;

		if (enc.length == 0) throw new TypeError('Buffer cannot have length 0');
		var keyTypeByte = enc[0];
		if (!(keyTypeByte == 0x05 || keyTypeByte == 0x06)) throw new Error('Unknown keyType');

		var ed25519ExpectedSize = 5 + sodium.crypto_sign_publickeybytes + sodium.crypto_sign_secretkeybytes;
		var c25519ExpectedSize = 5 + sodium.crypto_box_publickeybytes + sodium.crypto_box_secretkeybytes;
		var decodedKeyPair = {};

		var bufIndex = 1;
		if (keyTypeByte == 0x05){ //Curve25519
			//Check that length is respected.
			if (enc.length != c25519ExpectedSize) throw new TypeError('Invalid size for Curve25519 key buffer');
			decodedKeyPair.keyType = 'curve25519';
			//Reading claimed public key size and check validity
			var advPubKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPubKeySize != sodium.crypto_box_publickeybytes) throw new Error('Corrupted key buffer');
			//Reading public key
			var pubKey = new Uint8Array(sodium.crypto_box_publickeybytes);
			for (var i = 0; i < sodium.crypto_box_publickeybytes; i++){
				pubKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.publicKey = pubKey;
			bufIndex += sodium.crypto_box_publickeybytes;
			//Reading claimed private key size and check validity
			var advPrivKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPrivKeySize != sodium.crypto_box_secretkeybytes) throw new Error('Corrupted key buffer');
			//Reading private key
			var privKey = new Uint8Array(sodium.crypto_box_secretkeybytes);
			for (var i = 0; i < sodium.crypto_box_secretkeybytes; i++){
				privKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.privateKey = privKey;
			bufIndex += sodium.crypto_box_secretkeybytes;
		} else { //Ed25519
			//Check that length is respected
			if (enc.length != ed25519ExpectedSize) throw new TypeError('Invalid size for Ed25519 key buffer');
			decodedKeyPair.keyType = 'ed25519';
			//Reading claimed public key size
			var advPubKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPubKeySize != sodium.crypto_sign_publickeybytes) throw new Error('Corrupted key buffer');
			//Reading public key
			var pubKey = new Uint8Array(sodium.crypto_sign_publickeybytes);
			for (var i = 0; i < sodium.crypto_sign_publickeybytes; i++){
				pubKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.publicKey = pubKey;
			bufIndex += sodium.crypto_sign_publickeybytes;
			//Reading claimed private key size and check validity
			var advPrivKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPrivKeySize != sodium.crypto_sign_secretkeybytes) throw new Error('Corrupted key buffer');
			//Reading private key
			var privKey = new Uint8Array(sodium.crypto_sign_secretkeybytes);
			for (var i = 0; i < sodium.crypto_sign_secretkeybytes; i++){
				privKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.privateKey = privKey;
			bufIndex += sodium.crypto_sign_secretkeybytes;
		}

		return decodedKeyPair;
	}

	/* Encrypted buffer format. Numbers are in big endian
    * 2 bytes : r (unsigned short)
    * 2 bytes : p (unsigned short)
    * 4 bytes : opsLimit (unsigned long)
    * 2 bytes: salt size (sn, unsigned short)
    * 2 bytes : nonce size (ss, unsigned short)
    * 4 bytes : key buffer size (x, unsigned long)
    * sn bytes: salt
    * ss bytes : nonce
    * x bytes : encrypted data buffer (with MAC appended to it)
    */

	function scryptEncrypt(buffer, password){
		if (!(buffer && buffer instanceof Uint8Array)) throw new TypeError('Buffer must be a Uint8Array');
		if (!(typeof password == 'string' || password instanceof Uint8Array)) throw new TypeError('Password must be a string or a Uint8Array buffer');

		//console.log('Key plain text: ' + to_hex(buffer));

		var r = 8, p = 1, opsLimit = 16384; //Scrypt parameters
		var saltSize = 8;
		var nonceSize = sodium.crypto_secretbox_noncebytes;
		var totalSize = 16 + saltSize + nonceSize + buffer.length + sodium.crypto_secretbox_macbytes;

		//console.log('r: ' + 8 + '\np: ' + p + '\nopsLimit: ' + opsLimit + '\nsaltSize: ' + saltSize + '\nnonceSize: ' + nonceSize);

		var b = new Uint8Array(totalSize);
		var bIndex = 0;

		//Writing r and p
		b[bIndex] = (r >> 8);
		b[bIndex+1] = r;
		bIndex += 2;
		b[bIndex] = (p >> 8);
		b[bIndex+1] = p;
		bIndex += 2;
		//Writing opsLimit
		for (var i = 4; i > 0; i--){
			b[ bIndex ] = (opsLimit >> (8 * (i - 1))) % 256;
			//console.log('opsLimit[' + (5 - i).toString() +'] : ' + ((opsLimit >> (8 * (i - 1))) % 256).toString());
			bIndex++;
		}
		//bIndex += 8;
		//Writing saltSize
		b[bIndex] = (saltSize >> 8);
		b[bIndex+1] = saltSize;
		bIndex += 2;
		//Writing nonceSize
		b[bIndex] = (nonceSize >> 8);
		b[bIndex+1] = nonceSize;
		bIndex += 2;
		//Writing encryptedbuffer size
		var encContentSize = buffer.length + sodium.crypto_secretbox_macbytes;
		b[bIndex] = (encContentSize >> 24);
		b[bIndex+1] = (encContentSize >> 16);
		b[bIndex+2] = (encContentSize >> 8);
		b[bIndex+3] = encContentSize;
		bIndex += 4;
		//Writing salt
		var salt = randomBuffer(saltSize);
		//console.log('Salt: ' + to_hex(salt));
		for (var i = 0; i < saltSize; i++){
			b[ bIndex + i ] = salt[i];
		}
		bIndex += saltSize;
		//Writing nonce
		var nonce = randomBuffer(nonceSize);
		//console.log('Nonce: ' + to_hex(nonce));
		for (var i = 0; i < nonceSize; i++){
			b[ bIndex + i ] = nonce[i];
		}
		bIndex += nonceSize;

		//Derive password into encryption key
		var encKeyLength = sodium.crypto_secretbox_keybytes;
		var encKey = sodium.crypto_pwhash_scryptsalsa208sha256_ll(password, salt, opsLimit, r, p, encKeyLength);
		//console.log('Encryption key: ' + to_hex(encKey));
		//Encrypt the content and write it
		var cipher = sodium.crypto_secretbox_easy(buffer, nonce, encKey);
		for (var i = 0; i < cipher.length; i++){
			b[bIndex+i] = cipher[i];
		}
		bIndex += cipher.length;
		//console.log('Ciphertext: ' + to_hex(cipher));
		return b;
	}

	function scryptDecrypt(buffer, password){
		if (!(buffer && buffer instanceof Uint8Array)) throw new TypeError('Buffer must be a Uint8Array');
		if (!(typeof password == 'string' || passowrd instanceof Uint8Array)) throw new TypeError('password must be a string or a Uint8Array buffer');
		var minRemainingSize = 16; //16 bytes from the above format description

		if (in_avail() < minRemainingSize) throw new RangeError('Invalid encrypted buffer format');

		var r = 0, p = 0, opsLimit = 0, saltSize = 0, nonceSize = 0, encBufferSize = 0;
		var opsLimitBeforeException = 4194304;
		var rIndex = 0;

		//Reading r
		r = (buffer[rIndex] << 8) + buffer[rIndex+1];
		rIndex += 2;
		minRemainingSize -= 2;

		//Reading p
		p = (buffer[rIndex] << 8) + buffer[rIndex+1];
		rIndex += 2;
		minRemainingSize -= 2;

		//Reading opsLimit
		for (var i = 3; i >= 0; i--){
			opsLimit += (buffer[rIndex] << (8*i));
			//console.log('opsLimitPart[' + (4 - i).toString() + ']:' + (buffer[rIndex] << (8*i)));
			rIndex++;
		}
		minRemainingSize -= 4;

		if (opsLimit > opsLimitBeforeException) throw new RangeError('opsLimit over the authorized limit of ' + opsLimitBeforeException + ' (limited for performance issues)');

		//Reading salt size
		saltSize = (buffer[rIndex] << 8) + buffer[rIndex+1];
		rIndex += 2;
		minRemainingSize -= 2;
		minRemainingSize += saltSize;

		//Reading nonce
		nonceSize = (buffer[rIndex] << 8) + buffer[rIndex+1];
		rIndex += 2;
		minRemainingSize -= 2;
		minRemainingSize += nonceSize;

		//console.log('r: ' + 8 + '\np: ' + p + '\nopsLimit: ' + opsLimit + '\nsaltSize: ' + saltSize + '\nnonceSize: ' + nonceSize);

		if (in_avail() < minRemainingSize) throw new RangeError('Invalid encrypted buffer format');

		if (nonceSize != sodium.crypto_secretbox_noncebytes) throw new RangeError('Invalid nonce size');

		//Reading encrypted buffer length
		for (var i = 3; i >= 0; i--){
			encBufferSize += (buffer[rIndex] << (8*i));
			rIndex++;
		}
		minRemainingSize -= 4;
		minRemainingSize += encBufferSize;

		if (in_avail() < minRemainingSize) throw new RangeError('Invalid encrypted buffer format');

		//Reading salt
		var salt = new Uint8Array(saltSize);
		for (var i = 0; i < saltSize; i++){
			salt[i] = buffer[rIndex+i];
		}
		rIndex += saltSize;
		minRemainingSize -= saltSize;
		//console.log('Salt: ' + to_hex(salt));

		//Reading nonce
		var nonce = new Uint8Array(nonceSize);
		for (var i = 0; i < nonceSize; i++){
			nonce[i] = buffer[rIndex+i];
		}
		rIndex += nonceSize;
		minRemainingSize -= nonceSize;
		//console.log('Nonce: ' + to_hex(nonce));

		//Deriving password into encryption key
		var encKeyLength = sodium.crypto_secretbox_keybytes;
		var encKey = sodium.crypto_pwhash_scryptsalsa208sha256_ll(password, salt, opsLimit, r, p, encKeyLength);
		//console.log('Encryption key: ' + to_hex(encKey));

		var cipherText = new Uint8Array(encBufferSize );
		for (var i = 0; i < encBufferSize; i++){
			cipherText[i] = buffer[rIndex+i];
		}
		rIndex += encBufferSize;
		minRemainingSize -= encBufferSize;

		//Decrypting the ciphertext
		//console.log('Ciphertext: ' + to_hex(cipherText));
		var plainText = sodium.crypto_secretbox_open_easy(cipherText, nonce, encKey);
		//console.log('Key plain text:' + to_hex(plainText));
		return plainText; //If returned result is undefined, then invalid password (or corrupted buffer)

		function in_avail(){return buffer.length - rIndex;}

	}

	function loadKey(keyBuffer, password){
		if (!((typeof keyBuffer == 'string' && is_hex(keyBuffer)) || keyBuffer instanceof Uint8Array)) throw new TypeError('keyBuffer must either be a hex-string or a buffer');
		if (password && !(typeof password == 'string' || password instanceof Uint8Array)) throw new TypeError('password must either be a string or a buffer');

		var b = (keyBuffer instanceof Uint8Array ? keyBuffer : from_hex(keyBuffer));
		if (password){
			var keyType = b[0];
			var encryptedKeyBuffer = new Uint8Array(b.length - 1);
			for (var i = 1; i < b.length; i++){
				encryptedKeyBuffer[i-1] = b[i];
			}
			var decryptedKeyBuffer = scryptDecrypt(encryptedKeyBuffer, password);
			if (!decryptedKeyBuffer){
				throw new Error('Invalid password or corrupted buffer!');
			}
			//console.log('Decrypted encoded key pair: ' + to_hex(decryptedKeyBuffer));
			return keyDecode(decryptedKeyBuffer);
		} else {
			return keyDecode(b);
		}
	}

	function saveKey(keyPair, password){
		if (typeof keyPair != 'object') throw new TypeError('keyPair must be an object');
		if (!(typeof password == 'string' || password instanceof Uint8Array)) throw new TypeError('password must either be a string or a Uint8Array buffer');
		var decodedKeyPair = {};

		decodedKeyPair.keyType = keyPair.keyType;
		if (!(decodedKeyPair.keyType == 'curve25519' || decodedKeyPair.keyType == 'ed25519')) throw new TypeError('Key type must either be Ed25519 or Curve25519');
		if (is_hex(keyPair.publicKey)){
			decodedKeyPair.publicKey = from_hex(keyPair.publicKey);
		} else if (keyPair.publicKey instanceof Uint8Array){
			decodedKeyPair.publicKey = keyPair.publicKey;
		} else throw new TypeError('publicKey must either be a hex-string or a buffer');
		if (is_hex(keyPair.privateKey)){
			decodedKeyPair.privateKey = from_hex(keyPair.privateKey);
		} else if (keyPair.privateKey instanceof Uint8Array){
			decodedKeyPair.privateKey = keyPair.privateKey;
		} else throw new TypeError('privateKey must either be a hex-string or a buffer');

		var encodedKeyPair = keyEncode(decodedKeyPair);
		//console.log('Encoded key pair: ' + to_hex(encodedKeyPair));
		if (password){
			var encryptedKeyBuffer = scryptEncrypt(encodedKeyPair, password);
			var savedKeyBuffer = new Uint8Array(encryptedKeyBuffer.length + 1);
			savedKeyBuffer[0] = (decodedKeyPair.keyType == 'curve25519' ? 0x05 : 0x06);
			for (var i = 0; i < encryptedKeyBuffer.length; i++){
				savedKeyBuffer[i+1] = encryptedKeyBuffer[i];
			}
			return savedKeyBuffer;
		} else return encodedKeyPair;
	}

	function buildPayload(keyPair, username, userAction, httpMethod, hostAndPath){
		if (typeof keyPair != 'object') throw new TypeError('keyPair must be an object');
		if (!(typeof username == 'string' && username.length > 0)) throw new TypeError('Username must be a string');
		if (!(typeof userAction == 'number' && userAction == Math.floor(userAction) && userAction >= 0 && userAction <= 3)) throw new TypeError('userAction must a byte between 0 and 3');
		var vId = getVerbId(httpMethod);
		if (!vId) throw new TypeError('Invalid HTTP method');

		var decodedKeyPair = {};

		if (is_hex(keyPair.publicKey)){
			decodedKeyPair.publicKey = from_hex(keyPair.publicKey);
		} else if (keyPair.publicKey instanceof Uint8Array){
			decodedKeyPair.publicKey = keyPair.publicKey;
		} else throw new TypeError('Forbidden type for public key');

		if (is_hex(keyPair.privateKey)){
			decodedKeyPair.privateKey = from_hex(keyPair.privateKey);
		} else if (keyPair.privateKey instanceof Uint8Array){
			decodedKeyPair.privateKey = keyPair.privateKey;
		} else throw new TypeError('Forbidden type for private key');

		if (decodedKeyPair.publicKey.length != sodium.crypto_sign_publickeybytes) throw new TypeError('Invalid public key size');
		if (decodedKeyPair.privateKey.length != sodium.crypto_sign_secretkeybytes) throw new TypeError('Invalid private key size');

		var usernameBuffer = sodium.encode_utf8(username);
		if (usernameBuffer.length > 255) throw new TypeError('Username cannot be more than 255 bytes long');

		var hpkaReqBuffer = buildPayloadWithoutSignature(decodedKeyPair, usernameBuffer, userAction);

		var hostAndPathBuf = sodium.encode_utf8(hostAndPath);
		var hostAndPathLength = hostAndPathBuf.length;
		var signedBlobLength = hpkaReqBuffer.length + hostAndPathLength + 1; //The 1 is for the HTTP verbId
		var signedBlob = new Uint8Array(signedBlobLength);
		//Copy hpkaReqBuffer + hostAndPath
		for (var i = 0; i < hpkaReqBuffer.length; i++){
			signedBlob[i] = hpkaReqBuffer[i];
		}
		signedBlob[hpkaReqBuffer.length] = vId;
		for (var i = hpkaReqBuffer.length + 1, j = 0; i < signedBlobLength; i++, j++){
			signedBlob[i] = hostAndPathBuf[j];
		}

		//Sign and return HPKA headers
		var hpkaSignature = sodium.crypto_sign_detached(signedBlob, decodedKeyPair.privateKey);
		return {'req': to_base64(hpkaReqBuffer, true), 'sig': to_base64(hpkaSignature, true)};
	}

	function buildPayloadWithoutSignature(keyPair, username, userAction){
		var bufferLength = 0;
		bufferLength += 1; //Protocol version byte
		bufferLength += 8; //Timestamp bytes
		bufferLength += 1; //Username length byte
		bufferLength += username.length; //Reserving bytes for username
		bufferLength += 1; //HPKA actionType
		bufferLength += 1; //KeyType

		bufferLength += 2; //Public key length field
		bufferLength += sodium.crypto_sign_publickeybytes;

		var buffer = new Uint8Array(bufferLength);
		var offset = 0;

		//Protocol version
		buffer[0] = 0x01;
		offset++;
		//Writing the timestamp
		var timestamp = Math.floor(Number(Date.now()) / 1000);
		for (var i = 8; i > 0; i--){
			buffer[offset] = timestamp >> (8 * (i - 1));
			offset++;
		}
		//Writing the username length, then the username itself
		buffer[offset] = username.length;
		offset++;
		for (var i = 0; i < username.length; i++){
			buffer[offset+i] = username[i];
		}
		offset += username.length;
		//Writing the actionType
		buffer[offset] = userAction;
		offset++;
		//Writing the key type (Ed25519 == 0x08)
		buffer[offset] = 0x08;
		offset++;
		//Writing the public key length
		buffer[offset] = sodium.crypto_sign_publickeybytes >> 8;
		buffer[offset+1] = sodium.crypto_sign_publickeybytes;
		offset += 2;
		//Writing the public key
		for (var i = 0; i < keyPair.publicKey.length; i++){
			buffer[offset+i] = keyPair.publicKey[i];
		}
		offset += keyPair.publicKey.length;
		return buffer;
	}

	function randomBuffer(size){
		if (!(typeof size == 'number' && size > 0 && Math.floor(size) == size)) throw new TypeError('size must be a strictly positive integer');
		var b = new Uint8Array(size);
		window.crypto.getRandomValues(b);
		return b;
	}

	lib.supportedAlgorithms = supportedAlgorithms;
	lib.createIdentityKey = createKey;
	lib.scryptEncrypt = scryptEncrypt;
	lib.scryptDecrypt = scryptDecrypt;
	lib.loadKey = loadKey;
	lib.saveKey = saveKey;
	lib.buildPayload = buildPayload;
	lib.Client = client;
	lib.defaultAgent = defaultAgent;

	return lib;
})();
