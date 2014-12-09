var hpka = (function(){
	var lib = {};

	if (!libsodium) throw new Error('libsodium is missing!');

	function supportedAlgorithms(){return ['ed25519'];}
	lib.supportedAlgorithms = supportedAlgorithms;

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

	function createKey(password){
		if (password && !(password instanceof Uint8Array || typeof password == 'string')) throw new TypeError('When defined, password must either be a string or a Uint8Array');
		var ed25519Seed = randomBuffer(libsodium.crypto_sign_seedbytes);
		var ed25519KeyPair = libsodium.crypto_sign_seed_keypair(ed25519Seed);

		if (password){
			throw new Error('Key generation with password not implemented yet');
		} else return keyEncode(ed25519KeyPair, 'ed25519');
	}
	lib.createIdentityKey = createKey;

	function changeKeyPassword(keyBuffer, currentPassword, newPassword){

	}
	lib.changeKeyPassword = changeKeyPassword;

	function keyEncode(keyPair, keyType){
		if (typeof keyPair != 'object') throw new TypeError('keyPair must be an object');
		if (!(keyPair.publicKey && (keyPair.privateKey || keyPair.secretKey))) throw new TypeError('keyPair must contain public and private keys');
		if (typeof keyType != 'string') throw new TypeError('keyType must be a string');
		if (!(keyType == 'ed25519' || keyType == 'curve25519')) throw new TypeError('key must either be ed25519 or curve25519');

		//Decode hex if provided in hex
		var decodedKeyPair = {};
		var publicKeyParam = keyPair.publicKey;
		if (libsodium.is_hex(publicKeyParam)){
			decodedKeyPair.publicKey = libsodium.from_hex(publicKeyParam);
		} else if (publicKeyParam instanceof Uint8Array){
			decodedKeyPair.publicKey = publicKeyParam;
		} else throw new TypeError('Invalid public key format. Must either be a Uint8Array or a hex-string');

		var privateKeyParam = keyPair.privateKey || keyPair.secretKey;
		if (libsodium.is_hex(privateKeyParam)){
			decodedKeyPair.privateKey = libsodium.from_hex(privateKeyParam);
		} else if (privateKeyParam instanceof Uint8Array){
			decodedKeyPair.privateKey = privateKeyParam;
		} else throw new TypeError('Invalid private key format. Must either be a Uint8Array or a hex-string');

		if (keyType == 'ed25519'){
			if (decodedKeyPair.publicKey.length != libsodium.crypto_sign_publickeybytes) throw new Error('Ed25519 public key must be ' + libsodium.crypto_sign_publickeybytes + ' bytes long, and not ' + decodedKeyPair.publicKey.length);
			if (decodedKeyPair.privateKey.length != libsodium.crypto_sign_secretkeybytes) throw new Error('Ed25519 private key must be ' + libsodium.crypto_sign_secretkeybytes + ' bytes long, and not ' + decodedKeyPair.privateKey.length);
		} else {
			if (decodedKeyPair.publicKey.length != libsodium.crypto_box_publickeybytes) throw new Error('Curve25519 public key must be ' + libsodium.crypto_box_publickeybytes + ' bytes long, and not ' + decodedKeyPair.publicKey.length);
			if (decodedKeyPair.privateKey.length != libsodium.crypto_box_secretkeybytes) throw new Error('Curve25519 private key must be' + libsodium.crypto_box_secretkeybytes + ' bytes long, and not ' + decodedKeyPair.privateKey.length);
		}

		// 5 = 1 byte for keyType + 2 bytes for sk length + 2 bytes for pk length
		var curve25519EncSize = 5 + libsodium.crypto_box_secretkeybytes + libsodium.crypto_box_publickeybytes;
		var ed25519EncSize = 5 + libsodium.crypto_sign_secretkeybytes + libsodium.crypto_sign_publickeybytes;

		var encodedB = new Uint8Array(keyType == 'ed25519' ? ed25519EncSize : curve25519EncSize);
		//Writing keyType byte
		var bufIndex = 1;
		encodedB[0] = (keyType == 'curve25519' ? 0x05 : 0x06);
		if (keyType == 'curve25519'){
			//Writing public key size
			encodedB[bufIndex] = libsodium.crypto_box_publickeybytes >> 8;
			encodedB[bufIndex+1] = libsodium.crypto_box_publickeybytes;
			bufIndex += 2;
			//Writing public key
			for (var i = 0; i < decodedKeyPair.publicKey.length; i++){
				encodedB[bufIndex + i] = decodedKeyPair.publicKey[i];
			}
			bufIndex += decodedKeyPair.publicKey.length;
			//Writing secret key size
			encodedB[bufIndex] = libsodium.crypto_box_secretkeybytes >> 8;
			encodedB[bufIndex+1] = libsodium.crypto_box_secretkeybytes;
			bufIndex += 2;
			//Writing secret key
			for (var i = 0; i < decodedKeyPair.privateKey.length; i++){
				encodedB[bufIndex+i] = decodedKeyPair.privateKey[i];
			}
			bufIndex += decodedKeyPair.privateKey.length;
		} else { //Ed25519
			//Writing public key size
			encodedB[bufIndex] = libsodium.crypto_sign_publickeybytes >> 8;
			encodedB[bufIndex+1] = libsodium.crypto_sign_publickeybytes;
			bufIndex += 2;
			//Writing public key
			for (var i = 0; i < decodedKeyPair.publicKey.length; i++){
				encodedB[bufIndex+i] = decodedKeyPair.publicKey[i];
			}
			bufIndex += decodedKeyPair.publicKey.length;
			//Writing secret key size
			encodedB[bufIndex] = libsodium.crypto_sign_secretkeybytes >> 8;
			encodedB[bufIndex] = libsodium.crypto_sign_secretkeybytes;
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
		if (typeof encodedKeyPair == 'string' && !libsodium.is_hex(encodedKeyPair)) throw new TypeError('When encodedKeyPair is a string, it must be hex encoded');

		var enc;
		if (typeof encodedKeyPair == 'string') enc = libsodium.from_hex(encodedKeyPair);
		else enc = encodedKeyPair;

		if (enc.length == 0) throw new TypeError('Buffer cannot have length 0');
		var keyTypeByte = enc[0];
		if (!(keyTypeByte == 0x05 || keyTypeByte == 0x06)) throw new Error('Unknown keyType');

		var ed25519ExpectedSize = 5 + libsodium.crypto_sign_publickeybytes + libsodium.crypto_sign_secretkeybytes;
		var c25519ExpectedSize = 5 + libsodium.crypto_box_publickeybytes + libsodium.crypto_box_secretkeybytes;
		var decodedKeyPair = {};

		var bufIndex = 1;
		if (keyTypeByte == 0x05){ //Curve25519
			//Check that length is respected.
			if (enc.length != c25519ExpectedSize) throw new TypeError('Invalid size for Curve25519 key buffer');
			decodedKeyPair.keyType = 'curve25519';
			//Reading claimed public key size and check validity
			var advPubKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPubKeySize != libsodium.crypto_box_publickeybytes) throw new Error('Corrupted key buffer');
			//Reading public key
			var pubKey = new Uint8Array(libsodium.crypto_box_publickeybytes);
			for (var i = 0; i < libsodium.crypto_box_publickeybytes; i++){
				pubKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.publicKey = pubKey;
			bufIndex += libsodium.crypto_box_publickeybytes;
			//Reading claimed private key size and check validity
			var advPrivKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPrivKeySize != libsodium.crypto_box_secretkeybytes) throw new Error('Corrupted key buffer');
			//Reading private key
			var privKey = new Uint8Array(libsodium.crypto_box_secretkeybytes);
			for (var i = 0; i < libsodium.crypto_box_secretkeybytes; i++){
				privKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.privateKey = privKey;
			bufIndex += libsodium.crypto_box_secretkeybytes;
		} else { //Ed25519
			//Check that length is respected
			if (enc.length != ed25519ExpectedSize) throw new TypeError('Invalid size for Ed25519 key buffer');
			decodedKeyPair.keyType = 'ed25519';
			//Reading claimed public key size
			var advPubKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPubKeySize != libsodium.crypto_sign_publickeybytes) throw new Error('Corrupted key buffer');
			//Reading public key
			var pubKey = new Uint8Array(libsodium.crypto_sign_publickeybytes);
			for (var i = 0; i < libsodium.crypto_sign_publickeybytes; i++){
				pubKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.publicKey = pubKey;
			bufIndex += libsodium.crypto_sign_publickeybytes;
			//Reading claimed private key size and check validity
			var advPrivKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPrivKeySize != libsodium.crypto_sign_secretkeybytes) throw new Error('Corrupted key buffer');
			//Reading private key
			var privKey = new Uint8Array(libsodium.crypto_sign_secretkeybytes);
			for (var i = 0; i < libsodium.crypto_sign_secretkeybytes; i++){
				privKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.privateKey = privKey;
			bufIndex += libsodium.crypto_sign_secretkeybytes;
		}

		return decodedKeyPair;
	}

	function scryptEncrypt(buffer, password){

	}

	function scryptDecrypt(buffer, password){

	}

	function buildPayload(keyPair, username, userAction, httpMethod, hostAndPath){

	}
	lib.buildPayload = buildPayload;
	
	function randomBuffer(size){
		if (!(typeof size == 'number' && size > 0 && Math.floor(size) == size)) throw new TypeError('size must be a strictly positive integer');
		var b = new Uint8Array(size);
		window.crypto.getRandomValues(b);
		return b;
	}

	return lib;
})();

/*
* CLIENT METHODS
*/
//Create a client key pair and returns its keyring
exports.createClientKey = function(keyType, options, filename, password, doNotReturn){
	if (!(keyType == 'ecdsa' || keyType == 'dsa' || keyType == 'rsa' || keyType == 'ed25519')) throw new TypeError("Invalid key type. Must be either 'ecdsa', 'dsa' or 'rsa'");
	if (password && !(Buffer.isBuffer(password) || typeof password == 'string')) throw new TypeError('When defined, password must either be a buffer or a string');
	var keyRing;
	if (keyType == 'ecdsa' || keyType == 'dsa' || keyType == 'rsa'){ //Crypto++ cases
		keyRing = new cryptopp.KeyRing();
		if (keyType == 'ecdsa'){
			//Options should be the curve name;
			var curveId = getCurveID(options);
			if (curveId >= 0x80) {
				//Binary curves not supported yet by node-cryptopp
				throw new TypeError('Unsupported curve');
			}
		} else if (keyType == 'rsa'){
			//Options should be key size
			var keySize = Number(options);
			if (Number.isNaN(keySize)) throw new TypeError('Invalid key size');
		} else if (keyType == 'dsa'){ //DSA case
			//Options should be key size
			var keySize = Number(options);
			if (Number.isNaN(keySize)) throw new TypeError('Invalid key size');
		}
		keyRing.createKeyPair(keyType, options, filename);
	} else if (keyType == 'ed25519'){ //Ed25519
		keyRing = new sodium.KeyRing();
		keyRing.createKeyPair('ed25519');
		if (password){
			keyRing.save(filename, undefined, password);
		} else {
			keyRing.save(filename);
		}
	}
	//console.log('Generated key type : ' + keyRing.publicKeyInfo().keyType);
	if (doNotReturn){
		keyRing.clear();
		return;
	}
	return keyRing;
};

exports.changeClientKeyPassword = function(keyFilename, oldPassword, newPassword){
	if (!fs.existsSync(keyFilename)) throw new TypeError('The key file doesn\'t exist');
	if (!(Buffer.isBuffer(oldPassword)))
	var keyFileType = new Buffer(1);
	var fileHandle = fs.openSync(keyFilename, 'rs'); //'rs' flag for readSync
	var bytesRead = fs.readSync(fileHandle, keyFileType, 0, 1, 0);
	fs.closeSync(fileHandle);
	if (bytesRead != 1) throw new Error('Error while reading the key file to determine the key type. Bytes read : ' + bytesRead);

	if (keyFileType[0] != 0x06) throw new TypeError('Only Ed25519 key files can be encrypted');

	var tempKeyRing = new sodium.KeyRing();
	var pubKey;
	try {
		pubKey = tempKeyRing.load(keyFilename, undefined, oldPassword);
	} catch (e){

	}
	if (!pubKey) throw new TypeError('invalid password, or the file is not encrypted');
	tempKeyRing.save(keyFilename, undefined, newPassword);
	tempKeyRing.clear();
};

//Client object builder
exports.client = function(keyFilename, usernameVal, password){
	if (typeof usernameVal != 'string') throw new TypeError('Username must be a string');
	var keyRing, username;
	//keyFilename is either the path to the key file, or the keyring instance
	if ((cryptopp && keyFilename instanceof cryptopp.KeyRing) || (sodium && keyFilename instanceof sodium.KeyRing)){
		username = usernameVal;
		keyRing = keyFilename;
		try {
			keyRing.publicKeyInfo()
		} catch (e){
			throw new TypeError('The passed KeyRing has no key loaded into it');
		}
	} else {
		if (!fs.existsSync(keyFilename)) throw new TypeError('Key file not found'); //Checking that the file exists
		if (password && !(Buffer.isBuffer(password) || typeof password == 'string')) throw new TypeError('When defined, password must either be a buffer or a string');
		var keyFileType = new Buffer(1);
		var fileHandle = fs.openSync(keyFilename, 'rs'); //'rs' flag for readSync
		var bytesRead = fs.readSync(fileHandle, keyFileType, 0, 1, 0);
		fs.closeSync(fileHandle);
		if (bytesRead != 1) throw new Error('Error while reading the key file to determine the key type. Bytes read : ' + bytesRead);
		//console.log('key type: ' + keyFileType.toJSON());
		if (keyFileType[0] < 0x05){ //A key file produced by cryptopp begins with "key"
			//console.log('Cryptopp keyring');
			keyRing = new cryptopp.KeyRing();
		} else if (keyFileType[0] == 0x06){ //Checking that, according the first byte, the key is a Ed25519 one
			//console.log('Sodium keyring');
			keyRing = new sodium.KeyRing();
		} else throw new TypeError('Unknown key file type: ' + keyFileType.toJSON());
		username = usernameVal;
		if (keyFileType[0] == 0x06 && password){ //Ed25519
			keyRing.load(keyFilename, undefined, password);
		} else {
			keyRing.load(keyFilename);
		}
		try{
			keyRing.publicKeyInfo();
		} catch(e){
			throw new TypeError("Invalid key file");
		}
	}

	var httpRef = http;
	var httpsRef = https;

	function stdReq(options, body, actionType, callback, errorHandler){
		if (!(options && typeof options == 'object')) throw new TypeError('"options" parameter must be defined and must be an object, according to the default http(s) node modules & node-hpka documentations');
		if (!(typeof actionType == 'number')) throw new TypeError('"actionType" parameter must be defined and must be a number');
		if (!(actionType >= 0x00 && actionType <= 0x02)) throw new TypeError('"actionType" parameter must be 0x00 <= actionType <= 0x02 when calling stdReq(). Note that keyRotations have their methods (because they require than a simple HPKA-Req blob and its signature');
		if (!(callback && typeof callback == 'function')) throw new TypeError('"callback" must be a function');
		if (errorHandler && typeof errorHandler != 'function') throw new TypeError('"errorHandler must be a function"');
		if (!options.headers) options.headers = {};
		if (!options.method) options.method = 'get';
		if (!(options.hostname && options.path)) throw new TypeError('hostname and path options must be specified')
		var hostnameAndPath = options.hostname + options.path;
		buildPayload(keyRing, username, actionType, hostnameAndPath, options.method, function(hpkaReq, signature){
			options.headers['HPKA-Req'] = hpkaReq;
			options.headers['HPKA-Signature'] = signature;
			var req;
			if (body && body instanceof fd){
				var initialHeaders = options.headers;
				options.headers = body.getHeaders();
				var initialHeadersNames = Object.keys(initialHeaders);
				for (var i = 0; i < initialHeadersNames.length; i++){
					options.headers[initialHeadersNames[i]] = initialHeaders[initialHeadersNames[i]];
				}
				options.headers['HPKA-Req'] = hpkaReq;
				options.headers['HPKA-Signature'] = signature;
			}
			if (options.protocol && options.protocol == 'https'){
				options.protocol = null;
				req = httpsRef.request(options, function(res){
					if (callback) callback(res);
				})
			} else {
				options.protocol = null;
				req = httpRef.request(options, function(res){
					if (callback) callback(res);
				});
			}
			if (errorHandler) req.on('error', errorHandler);
			if (body){
				if (Buffer.isBuffer(body) || typeof body == 'string'){
					req.write(body);
					req.end();
				} else if (fd && body instanceof fd){
					body.pipe(req);
				} else {
					var err = new TypeError('invalid request body type');
					if (errorHandler) errorHandler(err);
					else throw err;
					return;
				}
			} else req.end();
		});
	}

	this.request = function(options, body, callback, errorHandler){
		stdReq(options, body, 0x00, callback, errorHandler);
	};

	this.registerUser = function(options, callback, errorHandler, body){
		stdReq(options, body, 0x01, callback, errorHandler);
	};

	this.deleteUser = function(options, callback, errorHandler){
		stdReq(options, undefined, 0x02, callback, errorHandler);
	};

	this.rotateKeys = function(options, newKeyPath, callback, password, errorHandler, body){
		if (!(options && typeof options == 'object')) throw new TypeError('"options" parameter must be defined and must be an object, according to the default http(s) node modules & node-hpka documentations');
		if (!(newKeyPath && typeof newKeyPath == 'string')) throw new TypeError('"newKeyPath" parameter must be a string, a path to the file containing the new key you want to use');
		if (!(callback && typeof callback == 'function')) throw new TypeError('"callback" must be a function');
		if (errorHandler && typeof errorHandler != 'function') throw new TypeError('when defined, errorHandler must be a function');
		if (!options.headers) options.headers = {};
		if (!options.method) options.method = 'get';
		if (!fs.existsSync(newKeyPath)) throw new TypeError('The key file doesn\'t exist');

		if (password && !(Buffer.isBuffer(password) || typeof password == 'string')) throw new TypeError('When defined, password must either be a buffer or a string');

		if (!((options.host || options.hostname) && options.path)) throw new TypeError('hostname and path options must be defined');
		var hostname = options.hostname || options.host.replace(/:\d+/, '');
		var hostnameAndPath = hostname + options.path;
		if (!parseHostnameAndPath(hostnameAndPath)) throw new TypeError('invalid hostname and path values');

		var signReq = function(keyRing, req, callback){
			if (!keyRing) throw new TypeError('KeyRing has not been defined');
			if (!Buffer.isBuffer(req)) throw new TypeError('req must be a buffer');
			if (!(callback && typeof callback == 'function')) throw new TypeError('Callback must be a function');

			var reqLength = req.length;
			var signedMessageLength = reqLength + Buffer.byteLength(hostnameAndPath, 'utf8') + 1; //The additional byte is for verbID
			var signedMessage = new Buffer(signedMessageLength);
			req.copy(signedMessage);
			signedMessage[reqLength] = getVerbId(options.method);
			signedMessage.write(hostnameAndPath, reqLength + 1);

			if (cryptopp && keyRing instanceof cryptopp.KeyRing){
				keyRing.sign(signedMessage.toString('utf8'), 'base64', undefined, callback);
			} else if (sodium && keyRing instanceof sodium.KeyRing) {
				keyRing.sign(signedMessage, function(signature){
					callback(signature.toString('base64'));
				}, true); //Last parameter : detached signature
			} else throw new TypeError('Unknown KeyRing type');
		};

		var newKeyRing;

		//Checking the key type before loading the NEW key in the keyring
		var keyFileType = new Buffer(1);
		var fileHandle = fs.openSync(newKeyPath, 'rs');
		var bytesRead = fs.readSync(fileHandle, keyFileType, 0, 1, 0);
		fs.closeSync(fileHandle);
		if (bytesRead != 1) throw new Error('Error while reading the key file to determine the key type. Bytes read : ' + bytesRead);

		if (keyFileType[0] < 0x05){ //Then, cryptopp keyring
			newKeyRing = new cryptopp.KeyRing();
		} else if (keyFileType[0] == 0x06) { //Then, sodium keyring
			newKeyRing = new sodium.KeyRing();
		} else throw new TypeError('Unknown key file type : ' + keyFileType.toJSON());

		if (keyFileType[0] == 0x06 && password){
			newKeyRing.load(newKeyPath, undefined, password);
		} else {
			newKeyRing.load(newKeyPath);
		}

		//First we build the payload with the known key and sign it
		buildPayload(keyRing, username, 0x03, hostnameAndPath, options.method, function(req1, signature1){
			options.headers['HPKA-Req'] = req1;
			options.headers['HPKA-Signature'] = signature1;
			//Now we build a payload with the new key
			buildPayloadWithoutSignature(newKeyRing, username, 0x03, function(req2){
				var req2Encoded = req2.toString('base64');
				options.headers['HPKA-NewKey'] = req2Encoded;
				//Now we sign the that second payload using the keypair known to the server
				signReq(keyRing, req2, function(newKeySignature1){
					options.headers['HPKA-NewKeySignature'] = newKeySignature1;
					//Now we sign it again, this time using the new key
					signReq(newKeyRing, req2, function(newKeySignature2){
						options.headers['HPKA-NewKeySignature2'] = newKeySignature2;
						//Now we clear the "old" keyRing and replace its reference to the newKeyRing
						keyRing.clear();
						keyRing = newKeyRing;
						//Now we build the HTTP/S request and send it to the server
						if (fd && body instanceof fd){
							var authHeaders = options.headers;
							options.headers = body.getHeaders();
							var authHeadersList = Object.keys(authHeaders);
							for (var i = 0; i < authHeadersList.length; i++){
								options.headers[authHeadersList[i]] = authHeaders[authHeadersList[i]];
							}
						}
						var httpReq;
						if (options.protocol && options.protocol == 'https'){
							options.protocol = null;
							httpReq = httpsRef.request(options, function(res){
								callback(res);
							});
						} else {
							options.protocol = null;
							httpReq = httpRef.request(options, function(res){
								callback(res);
							});
						}
						if (errorHandler) httpReq.on('error', errorHandler);

						if (body){
							if (typeof body == 'string' || Buffer.isBuffer(body)){
								req.write(body);
								req.end();
							} else if (fd && body instanceof fd){
								body.pipe(req);
							} else throw new TypeError('unknown body type on key rotation request');
						} else httpReq.end();
					});
				})
			});
		});
	};

	this.setHttpMod = function(_httpRef){
		if (_httpRef){
			httpRef = _httpRef;
		} else httpRef = http;
	};

	this.setHttpsMod = function(_httpsRef){
		if (_httpsRef){
			httpsRef = _httpsRef;
		} else httpsRef = https;
	};

	this.clear = function(){
		keyRing.clear();
	};
};

function buildPayloadWithoutSignature(keyRing, username, actionType, callback, encoding){
	if (!(keyRing && ((cryptopp && keyRing instanceof cryptopp.KeyRing) || (sodium && keyRing instanceof sodium.KeyRing)))) throw new TypeError('keyRing must defined and an instance of cryptopp.KeyRing or sodium.KeyRing');
	if (!(username && typeof username == 'string')) throw new TypeError('username must be a string');
	if (username.length > 255) throw new TypeError('Username must be at most 255 bytes long');
	if (!(actionType && typeof actionType == 'number')) actionType = 0x00;
	if (!(actionType >= 0x00 && actionType <= 0x03)) throw new TypeError('Invalid actionType. Must be 0 <= actionType <= 3');
	if (!(callback && typeof callback == 'function')) throw new TypeError('A "callback" must be given, and it must be a function');
	var pubKey = keyRing.publicKeyInfo();
	//console.log('Pubkey used for payload : ' + JSON.stringify(pubKey));
	//Calculating the buffer length depending on key type
	var bufferLength = 0;
	bufferLength += 1; //Version number
	bufferLength += 8; //Timestamp
	bufferLength += 1; //Username length byte
	bufferLength += username.length; //Actual username length
	bufferLength += 1; //actionType
	bufferLength += 1; //keyType
	if (pubKey.keyType == 'ecdsa'){
		bufferLength += 1; //Curve ID
		bufferLength += 2; //PublicKey.x length field
		bufferLength += pubKey.publicKey.x.length / 2; //Actual publicKey.x length. Divided by 2 because of hex encoding (that will be removed)...
		bufferLength += 2; //PublicKey.y length field
		bufferLength += pubKey.publicKey.y.length / 2; //Actual publicKey.y length. Divided by 2 because of hex encoding (that will be removed)...
	} else if (pubKey.keyType == 'rsa'){
		bufferLength += 2; //Modulus length field
		bufferLength += pubKey.modulus.length / 2; //Actual modulus length. Divided by 2 because of hex encoding
		bufferLength += 2; //PublicExp length field
		bufferLength += pubKey.publicExponent.length / 2; //Actual publicExponent length. Divided by 2 because of hex encoding
	} else if (pubKey.keyType == 'dsa'){
		bufferLength += 2; //Prime field length field
		bufferLength += pubKey.primeField.length / 2; //Actual prime field length
		bufferLength += 2; //Divider length field
		bufferLength += pubKey.divider.length / 2; //Actual divider length
		bufferLength += 2; //Base length field
		bufferLength += pubKey.base.length / 2; //Actual base length
		bufferLength += 2; //Public element length field
		bufferLength += pubKey.publicElement.length / 2; //Actual public element length
	} else if (pubKey.keyType == 'ed25519'){
		bufferLength += 2; //Public key length field
		bufferLength += pubKey.publicKey.length / 2; //Actual public key length
	}
	//bufferLength += 10; //The 10 random bytes appended to the end of the payload; augments signature's entropy
	//Building the payload
	//console.log('Req payload length : ' + bufferLength);
	var buffer = new Buffer(bufferLength);
	var offset = 0;
	//Writing protocol version
	buffer[0] = 0x01;
	offset++;
	//Writing the timestamp
	var timestamp = Math.floor(Number(Date.now()) / 1000);
	//console.log('Timestamp at buildPayload : ' + timestamp);
	buffer.writeInt32BE(timestamp >> 31, offset);
	offset += 4;
	buffer.writeInt32BE(timestamp, offset, true);
	offset += 4;
	//Writing the username length, then the username itself
	buffer.writeUInt8(username.length, offset);
	offset++;
	buffer.write(username, offset, offset + username.length, 'ascii');
	offset += username.length;
	//Writing the actionType
	buffer.writeUInt8(actionType, offset);
	offset++;
	if (pubKey.keyType == 'ecdsa'){
		//Writing the key type
		buffer.writeUInt8(0x01, offset);
		offset++;
		//Writing publicKey.x
		buffer.writeUInt16BE(pubKey.publicKey.x.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.publicKey.x, offset, 'hex');
		offset += pubKey.publicKey.x.length / 2;
		//Writing publicKey.y
		buffer.writeUInt16BE(pubKey.publicKey.y.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.publicKey.y, offset, 'hex');
		offset += pubKey.publicKey.y.length / 2;
		//Writing the curveID
		buffer.writeUInt8(getCurveID(pubKey.curveName), offset);
		offset++;
	} else if (pubKey.keyType == 'rsa'){
		//Writing the key type
		buffer.writeUInt8(0x02, offset);
		offset++;
		//console.log('RSA params :\nModulus : ')
		//Writing the modulus
		buffer.writeUInt16BE(pubKey.modulus.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.modulus, offset, 'hex');
		offset += pubKey.modulus.length / 2;
		//Writing the public exponent
		buffer.writeUInt16BE(pubKey.publicExponent.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.publicExponent, offset, 'hex');
		offset += pubKey.publicExponent.length / 2;
	} else if (pubKey.keyType == 'dsa'){
		//Writing the key type
		buffer.writeUInt8(0x04, offset);
		offset++;
		//Mwaaaaaa3, why does DSA need so much variables....
		//Writing the prime field
		buffer.writeUInt16BE(pubKey.primeField.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.primeField, offset, 'hex');
		offset += pubKey.primeField.length / 2;
		//Writing the divider
		buffer.writeUInt16BE(pubKey.divider.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.divider, offset, 'hex');
		offset += pubKey.divider.length / 2;
		//Writing the base
		buffer.writeUInt16BE(pubKey.base.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.base, offset, 'hex');
		offset += pubKey.base.length / 2;
		//Writing public element
		buffer.writeUInt16BE(pubKey.publicElement.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.publicElement, offset, 'hex');
		offset += pubKey.publicElement.length / 2;
	} else if (pubKey.keyType == 'ed25519'){
		//Writing key type
		buffer.writeUInt8(0x08, offset);
		offset++;
		//Writing public key
		buffer.writeUInt16BE(pubKey.publicKey.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.publicKey.toUpperCase(), offset, 'hex');
		offset += pubKey.publicKey.length / 2;
	} else throw new TypeError('Unknown key type : ' + pubKey.keyType);

	var req = (encoding ? buffer.toString(encoding) : buffer);
	callback(req);
}

function buildPayload(keyRing, username, actionType, hostnameAndPath, verb, callback){
	if (!(hostnameAndPath && typeof hostnameAndPath == 'string' && parseHostnameAndPath(hostnameAndPath))) throw new TypeError('hostnameAndPath must be a valid string with hostname and path of the request concatenated');
	if (!(typeof verb == 'string' && getVerbId(verb))) throw new TypeError('invalid HTTP verb');
	if (!(callback && typeof callback == 'function')) throw new TypeError('callback must be a function');
	buildPayloadWithoutSignature(keyRing, username, actionType, function(req){
		//Note : req is already base64 encoded at this point...
		var reqEncoded = req.toString('base64');
		var reqByteLength = req.length;
		var signedMessageLength = reqByteLength + Buffer.byteLength(hostnameAndPath, 'utf8') + 1; //The one additional byte is for the verbID
		var signedMessage = new Buffer(signedMessageLength);
		req.copy(signedMessage);
		signedMessage[reqByteLength] = getVerbId(verb);
		signedMessage.write(hostnameAndPath, reqByteLength + 1);
		//console.log('Signed payload:\n' + signedMessage.toString('hex'));
		var pubKey = keyRing.publicKeyInfo();
		var keyType = pubKey.keyType;
		if (keyType == 'rsa' || keyType == 'dsa' || keyType == 'ecdsa'){
			keyRing.sign(signedMessage.toString('utf8'), 'base64', undefined, function(signature){
				callback(reqEncoded, signature); //node-cryptopp returns the signatures already base64-encoded
			});
		} else if (keyType == 'ed25519'){
			keyRing.sign(signedMessage, function(signature){
				if (!(Buffer.isBuffer(signature) && signature.length == sodium.api.crypto_sign_BYTES)) throw new TypeError('Invalid signature: ' + signature);
				callback(reqEncoded, signature.toString('base64'));
			}, true); //Last parameter : detached signature
		} else throw new TypeError('Unknown key type : ' + keyType);
	});
}

exports.buildPayload = buildPayload;

function parseHostnameAndPath(s){
	if (!(s && typeof s == 'string')) return false;
	var seperationIndex = s.indexOf('/');
	if (seperationIndex == -1) return false;
	var hostname = s.substring(0, seperationIndex - 1);
	var path = s.substring(seperationIndex);
	return {hostname: hostname, path: path};
}

function getBase64ByteLength(base64){
	if (!isValidBase64(base64)) throw new TypeError('invalid base64 string');
	var missingBytes = 0;
	if (base64.indexOf('=') > -1) missingBytes = 1;
	if (base64.indexOf('==') > -1) missingBytes = 2;
	return 3 * (base64.length / 4) - missingBytes;
}

function appendHostAndPathFromReq(reqBlob, httpReq, encoding){
	if (!(typeof reqBlob == 'string' || Buffer.isBuffer(reqBlob))) throw new TypeError('reqBlob must either be a string or an object');
	if (typeof httpReq != 'object') throw new TypeError('httpReq must be an object');
	if (encoding && typeof encoding != 'string') throw new TypeError('When defined, encoding must be a string');
	var host = httpReq.headers.hostname || httpReq.headers.host.replace(/:\d+/, '');
	if (!host) return undefined;
	var path = httpReq.url;
	var hostAndPath = host + path;
	var hostAndPathLength = Buffer.byteLength(hostAndPath, 'utf8') + 1; //The additional byte is for the verbID
	var reqBuffer;
	if (!Buffer.isBuffer(reqBlob)){
		reqBuffer = new Buffer(reqBlob, encoding || 'base64');
	} else reqBuffer = reqBlob;
	var signedBlob = new Buffer(reqBuffer.length + hostAndPathLength);
	reqBuffer.copy(signedBlob);
	signedBlob[reqBuffer.length] = getVerbId(httpReq.method);
	signedBlob.write(hostAndPath, reqBuffer.length + 1);
	return signedBlob;
}
