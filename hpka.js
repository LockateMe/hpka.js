/*
* HPKA in-browser client
* Written by Ahmad Ben Mrad
* Distributed under the MIT license
* See https://github.com/LockateMe/hpka.js for more info
*/
var hpka = (function(){
	var lib = {};

	if (!sodium) throw new Error('libsodium is missing')

	var is_hex = function(s){
		return typeof s == 'string' && s.length % 2 == 0 && /^([a-f]|[0-9])+$/i.test(s)
	}
	var from_hex = sodium.from_hex;
	var to_hex = sodium.to_hex;
	var from_base64 = sodium.from_base64;
	var to_base64 = sodium.to_base64;
	var buffer_to_string = sodium.uint8Array_to_String || sodium.to_string;
	var string_to_buffer = sodium.string_to_Uint8Array || sodium.from_string;

	var TwoPower16 = 1 << 16;
	var TwoPower32 = TwoPower16 * TwoPower16;

	var absMaxForSessionTTL = 45 * 365.25 * 24 * 3600; //1/1/2015 00:00:00 UTC, in seconds. A threshold just helping us determine whether the provided wantedSessionExpiration is a TTL or a timestamp

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

	function client(username, keyBuffer, password, sigProvider, scProvider, loadCallback, allowGetSessions){
		if (typeof username != 'string') throw new TypeError('username must be a string');
		if (!(keyBuffer && (keyBuffer instanceof Uint8Array || typeof keyBuffer == 'object'))) throw new TypeError('keyBuffer must be a Uint8Array');
		if (password && !(typeof password == 'string' || password instanceof Uint8Array)) throw new TypeError('passowrd must be a Uint8Array');

		if (sigProvider && typeof sigProvider != 'function') throw new TypeError('when provided, sigProvider must be a function');
		if (scProvider && typeof scProvider != 'function') throw new TypeError('when provided, scProvider must be a function');
		if (loadCallback && typeof loadCallback != 'function') throw new TypeError('when provided, loadCallback must be a function');

		//var signatureProvider = sigProvider || defaultSignatureProvider, scryptProvider = scProvider || defaultScryptProvider;

		var signatureProvider = sigProvider == null ? null : (sigProvider || defaultSignatureProvider);
		var scryptProvider = scProvider == null ? null : (scProvider || defaultScryptProvider);

		var httpAgent = defaultAgent;
		var _username, _password, _keyPair, _keyTtl, _keyClearTimeout, _sessions = {};
		_username = username;
		if (keyBuffer instanceof Uint8Array){ //KeyBuffer to be decoded
			if (scryptProvider){
				/*
				The reasons behind this double assignation :
				- The loaded key is returned if password is undefined
				- The loaded key is passed through the callback if password is provided
				*/
				_keyPair = loadKey(keyBuffer, password, undefined, scryptProvider, function(err, _kp){
					if (err){
						if (loadCallback){
							loadCallback(err);
							return;
						} else throw err;
					}
					_keyPair = _kp;
				});

			} else {
				_keyPair = loadKey(keyBuffer, password);
			}

		} else { //Standard keyPair object
			if (!isKeyPair(keyBuffer)) throw new TypeError('invalid keyBuffer/keyPair parameter');
			_keyPair = keyBuffer;
		}

		this.request = function(reqOptions, callback){
			if (typeof reqOptions != 'object') throw new TypeError('reqOptions must be an object');

			var hostname;
			if (typeof reqOptions.headers == 'object') hostname = reqOptions.headers['Host'] || reqOptions.headers['host'];
			hostname = hostname || reqOptions.host;

			if (_sessions[hostname]){
				doSessionReq(_sessions[hostname], reqOptions, callback);
			} else {
				doHpkaReq(0x00, reqOptions, callback);
			}
		};

		this.registerAccount = function(reqOptions, callback){
			doHpkaReq(0x01, reqOptions, callback);
		};

		this.deleteAccount = function(reqOptions, callback){
			doHpkaReq(0x02, reqOptions, callback);
		};

		this.createSession = function(reqOptions, sessionId, wantedSessionExpiration, callback){
			if (typeof callback != 'function') throw new TypeError('callback must be a function');

			var tNow = Math.floor(Date.now() / 1000);

			if (wantedSessionExpiration){
				if (typeof wantedSessionExpiration != 'number') throw new TypeError('when defined, wantedSessionExpiration must be a number');
				if (Math.floor(wantedSessionExpiration) != wantedSessionExpiration) throw new TypeError('when defined, wantedSessionExpiration must be an integer number');
				if (wantedSessionExpiration != 0 && wantedSessionExpiration < absMaxForSessionTTL){ //Provided value is a TTL; convert it to timestamp
					wantedSessionExpiration += tNow;
				}
				if (wantedSessionExpiration != 0){ //When a session life is defined, assert that the value is in the future
					if (wantedSessionExpiration <= tNow) throw new Error('internal error');
				}
			}

			doHpkaReq(0x04, reqOptions, function(err, statusCode, body, headers){
				if (err){
					callback(err);
					return;
				}
				//Check that response headers are present
				if (!headers){
					callback(new Error('Critical: didn\'t receive headers from httpAgent on createSession'));
					return;
				}
				//Check that the server indeed returned a hpka-session-expiration header
				var sessionIdExpiration = headers['HPKA-Session-Expiration'] || headers['hpka-session-expiration'];
				if (typeof sessionIdExpiration == 'undefined' || sessionIdExpiration == null){
					var err = 'NOT_ACCEPTED';
					callback(new Error(err));
					return;
				}
				//Getting the hostname of the server we connected to
				var hostname;
				if (typeof reqOptions.headers == 'object') hostname = reqOptions.headers['Host'] || reqOptions.headers['host'];
				hostname = hostname || reqOptions.host;

				//Saving the sessionId in the sessions hash
				_sessions[hostname] = sessionId;

				callback(undefined, statusCode, body, headers, sessionIdExpiration);

			}, sessionId, wantedSessionExpiration || 0);
		};

		this.revokeSession = function(reqOptions, sessionId, callback){
			doHpkaReq(0x05, reqOptions, function(err, statusCode, body, headers){
				if (err){
					callback(err);
					return;
				}

				var hostname;
				if (typeof reqOptions.headers == 'object') hostname = reqOptions.headers['Host'] || reqOptions.headers['host'];
				hostname = hostname || reqOptions.host;

				delete _sessions[hostname];

				callback(undefined, statusCode, body, headers);
			}, sessionId);
		};

		this.setHttpAgent = function(agent){
			if (typeof agent != 'function') throw new TypeError('agent must be a function');
			httpAgent = agent;
		};

		this.setSignatureProvider = function(sigProvider){
			if (typeof sigProvider != 'function') throw new TypeError('sigProvider must be a function');
			signatureProvider = sigProvider;
		};

		this.setScryptProvider = function(scProvider){
			if (typeof scProvider != 'function') throw new TypeError('scProvider must be a function');
			scryptProvider = scProvider;
		};

		this.setKeyTtl = function(ttl){
			if (!(typeof ttl == 'number' && ttl > 0 && Math.floor(ttl) == ttl)) throw new TypeError('ttl must be a strictly positive integer');
			_keyTtl = ttl;
			_keyClearTimeout = setTimeout(ttlEndHandler, _keyTtl);
		};

		this.resetKeyTtl = function(ttl){
			if (!(_keyClearTimeout && _keyTtl)) return;
			if (ttl && !(typeof ttl == 'number' && ttl > 0 && Math.floor(ttl) == ttl)) throw new TypeError('when defined, ttl must be a strictly positive integer');
			_keyTtl = _keyTtl || ttl;
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

		this.loadKey = function(keyBuffer, password, cb){
			if (cb && typeof cb != 'function') throw new TypeError('when defined, cb must be a function');
			if (cb){ //If a callback is provided, then load the key asynchronously using the scryptProvider
				loadKey(keyBuffer, password, undefined, scryptProvider, function(err, _kp){
					if (err){
						cb(err);
						return;
					}
					_keyPair = _kp;
					cb();
				});
			} else { //Else, load synchronously using the default sodium.crypto_pwhash_scryptsalsa208sha256_ll function
				_keyPair = loadKey(keyBuffer, password);
			}
		};

		this.keyLoaded = function(){
			return !!_keyPair;
		};

		this.setSessions = function(sessionsHash, merge){
			if (typeof sessionsHash != 'object') throw new TypeError('sessionsHash must be an object');
			if (merge) for (s in sessionsHash) _sessions[s] = sessionsHash[s];
			else _sessions = sessionsHash;
		};

		this.getSessions = function(){
			if (!allowGetSessions) throw new Error('Retrieving sessionIds is not allowed by this client instance');
			return clone(_sessions);
		};

		this.getSessionsReference = function(){
			if (!allowGetSessions) throw new Error('Retrieving sessionIds is not allowed by this client instance');
			return _sessions;
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

		function doHpkaReq(actionCode, reqOptions, callback, sessionId, sessionExpiration){
			if (!(typeof actionCode == 'number' && Math.floor(actionCode) == actionCode && actionCode >= 0x00 && actionCode <= 0x05)) throw new TypeError('Invalid actionCode');
			if (typeof reqOptions != 'object') throw new TypeError('reqOptions must be an object');
			if (typeof callback != 'function') throw new TypeError('callback must be a function');
			validateReqOptions(reqOptions);

			try {
				hpka.buildPayload(_keyPair, _username, actionCode, reqOptions.method, hostAndPath(reqOptions), signatureProvider, function(err, hpkaPayload){
					if (err){
						callback(err);
						return;
					}

					if (!reqOptions.headers) reqOptions.headers = {};
					reqOptions.headers['HPKA-Req'] = hpkaPayload.req;
					reqOptions.headers['HPKA-Signature'] = hpkaPayload.sig;
					httpAgent(reqOptions, function(err, statusCode, body, headers){
						if (err){
							callback(err);
							return;
						}
						//Check headers format. Interrupt execution and send error through callback if it fails
						headers = processHeaders(headers, reqOptions, callback);
						//if (!headers) return;
						//If this line is reached, then processHeaders succeeded
						//Look for HPKA Errors
						if (statusCode == 445){
							callback(new Error('HPKA-Error:' + (headers['HPKA-Error'] || headers['hpka-error'])), statusCode, body, headers);
							return;
						}
						//Pass the validated response elements to the calling function
						callback(undefined, statusCode, body, headers);
					});
				}, sessionId, sessionExpiration);
			} catch (e){
				callback(e);
			}
		}

		function doSessionReq(sessionId, reqOptions, callback){
			if (!((sessionId instanceof Uint8Array) || typeof sessionId == 'string')) throw new TypeError('sessionId must either be a string or a Uint8Array');
			if (sessionId.length == 0 || sessionId.length > 255) throw new TypeError('sessionId must be ]0; 256[ bytes long');
			if (typeof reqOptions != 'object') throw new TypeError('reqOptions must be an object');
			if (typeof callback != 'function') throw new TypeError('callback must be a function');
			validateReqOptions(reqOptions);

			try {
				if (!reqOptions.headers) reqOptions.headers = {};
				reqOptions.headers['HPKA-Session'] = buildSessionPayload(_username, sessionId);
				httpAgent(reqOptions, function(err, statusCode, body, headers){
					if (err){
						callback(err);
						return;
					}
					headers = processHeaders(headers, reqOptions, callback);
					//if (!headers) return;
					//If this line is reached, then processHeaders succeeded
					//Look for HPKA errors
					if (statusCode == 445){
						callback(new Error('HPKA-Error:' + (headers['HPKA-Error'] || headers['hpka-error'])), statusCode, body, headers);
						return;
					}
					//Pass the validated response elements to the calling function
					callback(undefined, statusCode, body, headers);
				});
			} catch (e){
				callback(e);
			}
		}

		function processHeaders(h, reqOptions, callback){
			if (!h){
				console.error('Critical: didn\'t receive headers from ' + reqOptions.host + reqOptions.path);
				return;
			}
			if (typeof h == 'object') return h;
			else if (typeof h == 'string') return headersObject(h);
			else {
				callback(new TypeError('Critical: invalid headers type ('  + typeof h + ')'));
				return;
			}
		}
	}

	/*
	* reqOptions: {host, port, path, method, headers, body, protocol}
	* callback: (err, statusCode, body, resHeaders)
	*/
	function defaultAgent(reqOptions, callback){
		if (typeof reqOptions != 'object') throw new TypeError('reqOptions must be an object');
		if (callback && typeof callback != 'function') throw new TypeError('when defined, callback must be a function');

		validateReqOptions(reqOptions);

		//console.log('Req options validated');

		var xhReq = new XMLHttpRequest();
		var reqUrl = reqOptions.protocol + '://' + reqOptions.host + ':' + reqOptions.port.toString() + reqOptions.path;
		var reqErr;
		var resHeaders;
		xhReq.open(reqOptions.method, reqUrl, !!callback);
		xhReq.onload = function(){
			//console.log('onload');
			resHeaders = xhReq.getAllResponseHeaders();
			if (typeof headers != 'object') resHeaders = headersObject(resHeaders);
			if (callback) callback(null, xhReq.status, xhReq.responseText, resHeaders);
		};
		xhReq.onerror = function(e){
			//console.log('onerror');
			console.log(e);
			reqErr = e;
			if (callback) callback(e);
		};
		xhReq.onabort = function(e){
			//console.log('onabort');
			reqErr = e;
			if (callback) callback(e);
		};
		/*xhReq.onreadystatechange = function(e){
			console.log('onreadystatechange')

		};*/

		//console.log('xhReq opened');

		var bodyToSend;

		if (reqOptions.body){
			if (typeof reqOptions.body == 'object' && !(reqOptions.body instanceof Uint8Array || reqOptions.body instanceof FormData)){
				xhReq.setRequestHeader('Content-Type', 'appplication/json');
				try {
					bodyToSend = JSON.stringify(reqOptions.body);
				} catch (e){
					throw new Error('Cannot stringify body object. Please check for circular references');
					return;
				}
			}
			else if (reqOptions.body instanceof Uint8Array) bodyToSend = reqOptions.body.buffer;
			else {
				console.log('Is formdata ? ' + (reqOptions.body instanceof FormData).toString());
				bodyToSend = reqOptions.body;
			}
		}

		if (reqOptions.headers){
			var headersNames = Object.keys(reqOptions.headers);
			for (var i = 0; i < headersNames.length; i++) xhReq.setRequestHeader(headersNames[i], reqOptions.headers[headersNames[i]]);
		}

		xhReq.send(bodyToSend);

		//console.log('Req has been sent');

		//The result has been passed through the callback. Hence, the call doesn't need to "return" anything
		if (callback) return;

		var syncObject = {};
		if (reqErr) syncObject.err = reqErr;
		else {
			syncObject.statusCode = xhReq.status;
			syncObject.headers = resHeaders;
			syncObject.body = xhReq.responseText;
		}
		return syncObject;
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
		if (reqOptions.body && !((reqOptions.body instanceof Uint8Array) || (reqOptions.body instanceof FormData) || typeof reqOptions.body == 'object' || typeof reqOptions.body == 'string')) throw new TypeError('when defined, reqOptions.body must either an object, a string, a Uint8Array or a FormData instance');
	}

	function createKey(password, scryptProvider, callback){
		if (password && !(password instanceof Uint8Array || typeof password == 'string')) throw new TypeError('When defined, password must either be a string or a Uint8Array');
		if (callback && typeof callback != 'function') throw new TypeError('when defined, callback must be a function');
		if (scryptProvider){
			if (typeof scryptProvider != 'function') throw new TypeError('when defined, scryptProvider must be a function');
			if (typeof callback != 'function') throw new TypeError('when scryptProvider is used, callback must be provided and must be a function');
		}
		var ed25519Seed = randomBuffer(sodium.crypto_sign_SEEDBYTES);
		var ed25519KeyPair = sodium.crypto_sign_seed_keypair(ed25519Seed);

		var keyBuffer = keyEncode(ed25519KeyPair, 'ed25519');

		if (callback){
			if (!password){
				callback(null, keyBuffer);
				return;
			}

			scryptEncrypt(keyBuffer, password, scryptProvider || defaultScryptProvider, function(err, _encryptedKeyBuffer){
				if (err){
					callback(err);
					return;
				}
				var finalBuf = new Uint8Array(_encryptedKeyBuffer.length + 1);
				finalBuf[0] = 0x06;
				for (var i = 0; i < _encryptedKeyBuffer.length; i++){
					finalBuf[i+1] = _encryptedKeyBuffer[i];
				}
				callback(null, finalBuf);
			});
		} else {
			if (password){
				var encryptedKeyBuffer = scryptEncrypt(keyBuffer, password);
				var finalBuf = new Uint8Array(encryptedKeyBuffer.length + 1); //Adding one byte at the beginng, for keyType
				finalBuf[0] = 0x06;
				for (var i = 0; i < encryptedKeyBuffer.length; i++){
					finalBuf[i+1] = encryptedKeyBuffer[i];
				}
				return finalBuf;
				//throw new Error('Key generation with password not implemented yet');
			} else return keyBuffer;
		}
	}

	/*function changeKeyPassword(keyBuffer, currentPassword, newPassword){

	}*/

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
			if (decodedKeyPair.publicKey.length != sodium.crypto_sign_PUBLICKEYBYTES) throw new Error('Ed25519 public key must be ' + sodium.crypto_sign_PUBLICKEYBYTES + ' bytes long, and not ' + decodedKeyPair.publicKey.length);
			if (decodedKeyPair.privateKey.length != sodium.crypto_sign_SECRETKEYBYTES) throw new Error('Ed25519 private key must be ' + sodium.crypto_sign_SECRETKEYBYTES + ' bytes long, and not ' + decodedKeyPair.privateKey.length);
		} else {
			if (decodedKeyPair.publicKey.length != sodium.crypto_box_PUBLICKEYBYTES) throw new Error('Curve25519 public key must be ' + sodium.crypto_box_PUBLICKEYBYTES + ' bytes long, and not ' + decodedKeyPair.publicKey.length);
			if (decodedKeyPair.privateKey.length != sodium.crypto_box_SECRETKEYBYTES) throw new Error('Curve25519 private key must be' + sodium.crypto_box_SECRETKEYBYTES + ' bytes long, and not ' + decodedKeyPair.privateKey.length);
		}

		// 5 = 1 byte for keyType + 2 bytes for sk length + 2 bytes for pk length
		var curve25519EncSize = 5 + sodium.crypto_box_SECRETKEYBYTES + sodium.crypto_box_PUBLICKEYBYTES;
		var ed25519EncSize = 5 + sodium.crypto_sign_SECRETKEYBYTES + sodium.crypto_sign_PUBLICKEYBYTES;

		var encodedB = new Uint8Array(keyType == 'ed25519' ? ed25519EncSize : curve25519EncSize);
		//Writing keyType byte
		var bufIndex = 1;
		encodedB[0] = (keyType == 'curve25519' ? 0x05 : 0x06);
		if (keyType == 'curve25519'){
			//Writing public key size
			encodedB[bufIndex] = sodium.crypto_box_PUBLICKEYBYTES >> 8;
			encodedB[bufIndex+1] = sodium.crypto_box_PUBLICKEYBYTES;
			bufIndex += 2;
			//Writing public key
			for (var i = 0; i < decodedKeyPair.publicKey.length; i++){
				encodedB[bufIndex + i] = decodedKeyPair.publicKey[i];
			}
			bufIndex += decodedKeyPair.publicKey.length;
			//Writing secret key size
			encodedB[bufIndex] = sodium.crypto_box_SECRETKEYBYTES >> 8;
			encodedB[bufIndex+1] = sodium.crypto_box_SECRETKEYBYTES;
			bufIndex += 2;
			//Writing secret key
			for (var i = 0; i < decodedKeyPair.privateKey.length; i++){
				encodedB[bufIndex+i] = decodedKeyPair.privateKey[i];
			}
			bufIndex += decodedKeyPair.privateKey.length;
		} else { //Ed25519
			//Writing public key size
			encodedB[bufIndex] = sodium.crypto_sign_PUBLICKEYBYTES >> 8;
			encodedB[bufIndex+1] = sodium.crypto_sign_PUBLICKEYBYTES;
			bufIndex += 2;
			//Writing public key
			for (var i = 0; i < decodedKeyPair.publicKey.length; i++){
				encodedB[bufIndex+i] = decodedKeyPair.publicKey[i];
			}
			bufIndex += decodedKeyPair.publicKey.length;
			//Writing secret key size
			encodedB[bufIndex] = sodium.crypto_sign_SECRETKEYBYTES >> 8;
			encodedB[bufIndex+1] = sodium.crypto_sign_SECRETKEYBYTES;
			bufIndex += 2;
			//Writing secret key
			for (var i = 0; i < decodedKeyPair.privateKey.length; i++){
				encodedB[bufIndex+i] = decodedKeyPair.privateKey[i];
			}
			bufIndex += decodedKeyPair.privateKey.length;
		}

		return encodedB;
	}

	function keyDecode(encodedKeyPair, resultEncoding){
		if (!(encodedKeyPair && (encodedKeyPair instanceof Uint8Array || typeof encodedKeyPair == 'string'))) throw new TypeError('Parameter encoded key pair must either be a Uint8Array or a string');
		if (typeof encodedKeyPair == 'string' && !is_hex(encodedKeyPair)) throw new TypeError('When encodedKeyPair is a string, it must be hex encoded');

		if (resultEncoding && typeof resultEncoding != 'string') throw new TypeError('when defined, resultEncoding must be a string');
		if (resultEncoding && !(resultEncoding == 'hex' || resultEncoding == 'base64')) throw new Error('when defined, resultEncoding must either be "hex" or "base64"');

		var enc;
		if (typeof encodedKeyPair == 'string') enc = from_hex(encodedKeyPair);
		else enc = encodedKeyPair;

		if (enc.length == 0) throw new TypeError('Buffer cannot have length 0');
		var keyTypeByte = enc[0];
		if (!(keyTypeByte == 0x05 || keyTypeByte == 0x06)) throw new Error('Unknown keyType');

		var ed25519ExpectedSize = 5 + sodium.crypto_sign_PUBLICKEYBYTES + sodium.crypto_sign_SECRETKEYBYTES;
		var c25519ExpectedSize = 5 + sodium.crypto_box_PUBLICKEYBYTES + sodium.crypto_box_SECRETKEYBYTES;
		var decodedKeyPair = {};

		var bufIndex = 1;
		if (keyTypeByte == 0x05){ //Curve25519
			//Check that length is respected.
			if (enc.length != c25519ExpectedSize) throw new TypeError('Invalid size for Curve25519 key buffer (maybe a password should be provided to hpka.loadKey() )');
			decodedKeyPair.keyType = 'curve25519';
			//Reading claimed public key size and check validity
			var advPubKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPubKeySize != sodium.crypto_box_PUBLICKEYBYTES) throw new Error('Corrupted key buffer');
			//Reading public key
			var pubKey = new Uint8Array(sodium.crypto_box_PUBLICKEYBYTES);
			for (var i = 0; i < sodium.crypto_box_PUBLICKEYBYTES; i++){
				pubKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.publicKey = pubKey;
			bufIndex += sodium.crypto_box_PUBLICKEYBYTES;
			//Reading claimed private key size and check validity
			var advPrivKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPrivKeySize != sodium.crypto_box_SECRETKEYBYTES) throw new Error('Corrupted key buffer');
			//Reading private key
			var privKey = new Uint8Array(sodium.crypto_box_SECRETKEYBYTES);
			for (var i = 0; i < sodium.crypto_box_SECRETKEYBYTES; i++){
				privKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.privateKey = privKey;
			bufIndex += sodium.crypto_box_SECRETKEYBYTES;
		} else { //Ed25519
			//Check that length is respected
			if (enc.length != ed25519ExpectedSize) throw new TypeError('Invalid size for Ed25519 key buffer (maybe a password should be provided to hpka.loadKey() )');
			decodedKeyPair.keyType = 'ed25519';
			//Reading claimed public key size
			var advPubKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPubKeySize != sodium.crypto_sign_PUBLICKEYBYTES) throw new Error('Corrupted key buffer');
			//Reading public key
			var pubKey = new Uint8Array(sodium.crypto_sign_PUBLICKEYBYTES);
			for (var i = 0; i < sodium.crypto_sign_PUBLICKEYBYTES; i++){
				pubKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.publicKey = pubKey;
			bufIndex += sodium.crypto_sign_PUBLICKEYBYTES;
			//Reading claimed private key size and check validity
			var advPrivKeySize = (enc[bufIndex] << 8) + enc[bufIndex+1];
			bufIndex += 2;
			if (advPrivKeySize != sodium.crypto_sign_SECRETKEYBYTES) throw new Error('Corrupted key buffer');
			//Reading private key
			var privKey = new Uint8Array(sodium.crypto_sign_SECRETKEYBYTES);
			for (var i = 0; i < sodium.crypto_sign_SECRETKEYBYTES; i++){
				privKey[i] = enc[bufIndex+i];
			}
			decodedKeyPair.privateKey = privKey;
			bufIndex += sodium.crypto_sign_SECRETKEYBYTES;
		}

		if (resultEncoding == 'hex'){
			decodedKeyPair.publicKey = to_hex(decodedKeyPair.publicKey);
			decodedKeyPair.privateKey = to_hex(decodedKeyPair.privateKey);
		} else if (resultEncoding == 'base64'){
			decodedKeyPair.publicKey = to_base64(decodedKeyPair.publicKey, true);
			decodedKeyPair.privateKey = to_base64(decodedKeyPair.privateKey, true);
		}

		return decodedKeyPair;
	}

	function isKeyPair(kp){
		if (typeof kp != 'object') return false;
		if (!(kp.keyType && kp.privateKey && kp.publicKey)) return false;
		if (kp.keyType != 'ed25519') return false;
		if (!(kp.publicKey instanceof Uint8Array && !isNullBuffer(kp.publicKey) && kp.publicKey.length == sodium.crypto_sign_PUBLICKEYBYTES)) return false;
		if (!(kp.privateKey instanceof Uint8Array && !isNullBuffer(kp.privateKey) && kp.privateKey.length == sodium.crypto_sign_SECRETKEYBYTES)) return false;
		return true;
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

	function scryptEncrypt(buffer, password, scryptProvider, callback){
		if (!(buffer && buffer instanceof Uint8Array)) throw new TypeError('Buffer must be a Uint8Array');
		if (!(typeof password == 'string' || password instanceof Uint8Array)) throw new TypeError('Password must be a string or a Uint8Array buffer');
		if (scryptProvider){
			if (typeof scryptProvider != 'function') throw new TypeError('when defined, scryptProvider must be a function');
			if (typeof callback != 'function') throw new TypeError('when scryptProvider is defined, callback must be defined and must be a function');
		}
		//console.log('Key plain text: ' + to_hex(buffer));

		var r = 8, p = 1, opsLimit = 16384; //Scrypt parameters
		var saltSize = 8;
		var nonceSize = sodium.crypto_secretbox_NONCEBYTES;
		var totalSize = 16 + saltSize + nonceSize + buffer.length + sodium.crypto_secretbox_MACBYTES;

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
		var encContentSize = buffer.length + sodium.crypto_secretbox_MACBYTES;
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
		var encKeyLength = sodium.crypto_secretbox_KEYBYTES;
		var encKey;
		if (scryptProvider){
			scryptProvider([password, salt, opsLimit, r, p, encKeyLength], function(err, _encKey){
				if (err){
					callback(err);
					return;
				}
				encKey = _encKey;
				endEncryption();
			});
		} else {
			encKey = sodium.crypto_pwhash_scryptsalsa208sha256_ll(password, salt, opsLimit, r, p, encKeyLength);
			return endEncryption();
		}
		//console.log('Encryption key: ' + to_hex(encKey));

		function endEncryption(){
			//Encrypt the content and write it
			var cipher = sodium.crypto_secretbox_easy(buffer, nonce, encKey);
			for (var i = 0; i < cipher.length; i++){
				b[bIndex+i] = cipher[i];
			}
			bIndex += cipher.length;
			//console.log('Ciphertext: ' + to_hex(cipher));
			if (scryptProvider) callback(null, b);
			else return b;
		}
	}

	function scryptDecrypt(buffer, password, scryptProvider, callback){
		if (!(buffer && buffer instanceof Uint8Array)) throw new TypeError('Buffer must be a Uint8Array');
		if (!(typeof password == 'string' || passowrd instanceof Uint8Array)) throw new TypeError('password must be a string or a Uint8Array buffer');
		if (scryptProvider){
			if (typeof scryptProvider != 'function') throw new TypeError('when defined, scryptProvider must be a function');
			if (typeof callback != 'function') throw new TypeError('when scryptProvider is defined, callback must be defined and must be a function');
		}

		var minRemainingSize = 16; //16 bytes from the above format description

		if (in_avail() < minRemainingSize){
			handleErr(new RangeError('Invalid encrypted buffer format'));
			return;
		}

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

		if (opsLimit > opsLimitBeforeException){
			handleErr(new RangeError('opsLimit over the authorized limit of ' + opsLimitBeforeException + ' (limited for performance issues)'));
			return;
		}
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

		if (in_avail() < minRemainingSize){
			handleErr(new RangeError('Invalid encrypted buffer format'));
			return;
		}
		if (nonceSize != sodium.crypto_secretbox_NONCEBYTES){
			handleErr(new RangeError('Invalid nonce size'));
			return;
		}

		//Reading encrypted buffer length
		for (var i = 3; i >= 0; i--){
			encBufferSize += (buffer[rIndex] << (8*i));
			rIndex++;
		}
		minRemainingSize -= 4;
		minRemainingSize += encBufferSize;

		if (in_avail() < minRemainingSize){
			handleErr(new RangeError('Invalid encrypted buffer format'));
			return;
		}

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
		var encKeyLength = sodium.crypto_secretbox_KEYBYTES;
		var encKey;
		if (scryptProvider){
			scryptProvider([password, salt, opsLimit, r, p, encKeyLength], function(err, _encKey){
				if (err){
					callback(err);
					return;
				}
				encKey = _encKey;
				endDecryption();
			});
		} else {
			encKey = sodium.crypto_pwhash_scryptsalsa208sha256_ll(password, salt, opsLimit, r, p, encKeyLength);
			return endDecryption();
		}

		function endDecryption(){
			//console.log('Encryption key: ' + to_hex(encKey));

			var cipherText = new Uint8Array(encBufferSize);
			for (var i = 0; i < encBufferSize; i++){
				cipherText[i] = buffer[rIndex+i];
			}
			rIndex += encBufferSize;
			minRemainingSize -= encBufferSize;

			//Decrypting the ciphertext
			var plainText = sodium.crypto_secretbox_open_easy(cipherText, nonce, encKey);

			if (scryptProvider) callback(null, plainText);
			else return plainText; //If returned result is undefined, then invalid password (or corrupted buffer)
		}

		function in_avail(){return buffer.length - rIndex;}

		function handleErr(e){
			if (scryptProvider && callback) callback(e);
			else throw e;
		}
	}

	function loadKey(keyBuffer, password, resultEncoding, scryptProvider, callback){
		if (!((typeof keyBuffer == 'string' && is_hex(keyBuffer)) || keyBuffer instanceof Uint8Array)) throw new TypeError('keyBuffer must either be a hex-string or a buffer');
		if (password && !(typeof password == 'string' || password instanceof Uint8Array)) throw new TypeError('password must either be a string or a buffer');

		if (scryptProvider){
			if (typeof scryptProvider != 'function') throw new TypeError('when defined, scryptProvider must be a function');
			if (typeof callback != 'function') throw new TypeError('when scryptProvider is defined, callback must be defined and must be a function');
		}

		var b = (keyBuffer instanceof Uint8Array ? keyBuffer : from_hex(keyBuffer));
		if (password){
			var keyType = b[0];
			var encryptedKeyBuffer = new Uint8Array(b.length - 1);
			for (var i = 1; i < b.length; i++){
				encryptedKeyBuffer[i-1] = b[i];
			}

			if (scryptProvider){
				scryptDecrypt(encryptedKeyBuffer, password, scryptProvider, function(err, _decryptedKeyBuffer){
					if (err){
						callback(err);
						return;
					}
					if (!_decryptedKeyBuffer){
						callback(new Error('Invalid password or corrupted buffer!'));
						return;
					}
					callback(null, keyDecode(_decryptedKeyBuffer, resultEncoding));
				});
			} else {
				var decryptedKeyBuffer = scryptDecrypt(encryptedKeyBuffer, password);
				if (!decryptedKeyBuffer){
					throw new Error('Invalid password or corrupted buffer!');
				}
				//console.log('Decrypted encoded key pair: ' + to_hex(decryptedKeyBuffer));
				return keyDecode(decryptedKeyBuffer, resultEncoding);
			}
		} else {
			return keyDecode(b, resultEncoding);
		}
	}

	function saveKey(keyPair, password, scryptProvider, callback){
		if (typeof keyPair != 'object') throw new TypeError('keyPair must be an object');
		if (password && !(typeof password == 'string' || password instanceof Uint8Array)) throw new TypeError('password must either be a string or a Uint8Array buffer');

		if (scryptProvider){
			if (typeof scryptProvider != 'function') throw new TypeError('when defined, scryptProvider must be a function');
			if (typeof callback != 'function') throw new TypeError('when scryptProvider is defined, callback must be defined and must be a function');
		}

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
			if (scryptProvider){
				scryptProvider(encodedKeyPair, password, scryptProvider, function(err, _encryptedKeyBuffer){
					if (err){
						callback(err);
						return;
					}
					var savedKeyBuffer = new Uint8Array(_encryptedKeyBuffer.length + 1);
					savedKeyBuffer[0] = (decodedKeyPair.keyType == 'curve25519' ? 0x05 : 0x06);
					for (var i = 0; i < _encryptedKeyBuffer.length; i++){
						savedKeyBuffer[i+1] = _encryptedKeyBuffer[i];
					}
					callback(null, _encryptedKeyBuffer);
				});
			} else {
				var encryptedKeyBuffer = scryptEncrypt(encodedKeyPair, password);
				var savedKeyBuffer = new Uint8Array(encryptedKeyBuffer.length + 1);
				savedKeyBuffer[0] = (decodedKeyPair.keyType == 'curve25519' ? 0x05 : 0x06);
				for (var i = 0; i < encryptedKeyBuffer.length; i++){
					savedKeyBuffer[i+1] = encryptedKeyBuffer[i];
				}
				return savedKeyBuffer;
			}
		} else return encodedKeyPair;
	}

	function buildPayload(keyPair, username, actionType, httpMethod, hostAndPath, sigProvider, callback, sessionId, sessionExpiration){
		if (typeof keyPair != 'object') throw new TypeError('keyPair must be an object');
		if (!(typeof username == 'string' && username.length > 0)) throw new TypeError('Username must be a string');
		if (!(typeof actionType == 'number' && actionType == Math.floor(actionType) && actionType >= 0 && actionType <= 5)) throw new TypeError('actionType must a byte between 0 and 5');
		if (sessionId && !((sessionId instanceof Uint8Array || typeof sessionId == 'string') && sessionId.length > 0 && sessionId.length < 256)) throw new TypeError('when defined, sessionId must be a non-null buffer or string, max 255 bytes long');
		if (sessionExpiration){
			if (typeof sessionExpiration != 'number') throw new TypeError('when defined, sessionExpiration must be a number');
			if (Math.floor(sessionExpiration) != sessionExpiration) throw new TypeError('when defined, sessionExpiration must be an integer number');
			if (sessionExpiration < 0 || (sessionExpiration > 0 && Math.floor(Date.now() / 1000) > sessionExpiration)) throw new TypeError('when defined, sessionExpiration must either be equal to zero or UTC Unix epoch that is not yet passed');
		}

		if (actionType == 0x04 || actionType == 0x05){
			if (!sessionId) throw new TypeError('when actionType == 0x04 or actionType == 0x05, sessionId must be defined');
		}

		var vId = getVerbId(httpMethod);
		if (!vId) throw new TypeError('Invalid HTTP method');

		if (sigProvider){
			if (typeof sigProvider != 'function') throw new TypeError('when defined, sigProvider must be a function');
			if (typeof callback != 'function') throw new TypeError('when sigProvider is defined, callback must also be defined and must be a function');
		}
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

		if (decodedKeyPair.publicKey.length != sodium.crypto_sign_PUBLICKEYBYTES) throw new TypeError('Invalid public key size');
		if (decodedKeyPair.privateKey.length != sodium.crypto_sign_SECRETKEYBYTES) throw new TypeError('Invalid private key size');

		var usernameBuffer = string_to_buffer(username);
		if (usernameBuffer.length > 255) throw new TypeError('Username cannot be more than 255 bytes long');

		var hpkaReqBuffer = buildPayloadWithoutSignature(decodedKeyPair, usernameBuffer, actionType, sessionId, sessionExpiration);

		var hostAndPathBuf = string_to_buffer(hostAndPath);
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
		if (sigProvider){ //Do it asynchronously using sigProvider
			sigProvider(signedBlob, decodedKeyPair.privateKey, function(err, hpkaSignature){
				if (err) callback(err);
				else callback(null, {'req': to_base64(hpkaReqBuffer, true), 'sig': to_base64(hpkaSignature, true)});
			});
		} else { //Do it synchronously
			var hpkaSignature = sodium.crypto_sign_detached(signedBlob, decodedKeyPair.privateKey);
			var resultObj = {'req': to_base64(hpkaReqBuffer, true), 'sig': to_base64(hpkaSignature, true)};
			if (callback) callback(null, resultObj);
			else return resultObj;
		}
	}

	function buildPayloadWithoutSignature(keyPair, username, actionType, sessionId, sessionExpiration){
		var bufferLength = 0;
		bufferLength += 1; //Protocol version byte
		bufferLength += 8; //Timestamp bytes
		bufferLength += 1; //Username length byte
		bufferLength += username.length; //Reserving bytes for username
		bufferLength += 1; //HPKA actionType
		bufferLength += 1; //KeyType

		bufferLength += 2; //Public key length field
		bufferLength += sodium.crypto_sign_PUBLICKEYBYTES;

		if (actionType == 0x04 || actionType == 0x05){
			//Add sessionId, and a byte to state its length
			bufferLength += 1 + sessionId.length;
			//Add a session expiration date
			if (actionType == 0x04 && sessionExpiration) bufferLength += 8;
		}

		var buffer = new Uint8Array(bufferLength);
		var offset = 0;

		//Protocol version
		buffer[0] = 0x01;
		offset++;
		//Writing the timestamp
		var timestamp = Math.floor(Number(Date.now()) / 1000);
		var timestampParts = splitUInt(timestamp);
		writeUInt32BE(timestampParts.left, offset, buffer);
		offset += 4;
		writeUInt32BE(timestampParts.right, offset, buffer);
		offset += 4;
		//Writing the username length, then the username itself
		buffer[offset] = username.length;
		offset++;
		for (var i = 0; i < username.length; i++){
			buffer[offset+i] = username[i];
		}
		offset += username.length;
		//Writing the actionType
		buffer[offset] = actionType;
		offset++;
		//Writing the key type (Ed25519 == 0x08)
		buffer[offset] = 0x08;
		offset++;
		//Writing the public key length
		buffer[offset] = sodium.crypto_sign_PUBLICKEYBYTES >> 8;
		buffer[offset+1] = sodium.crypto_sign_PUBLICKEYBYTES;
		offset += 2;
		//Writing the public key
		for (var i = 0; i < keyPair.publicKey.length; i++){
			buffer[offset+i] = keyPair.publicKey[i];
		}
		offset += keyPair.publicKey.length;

		if (actionType == 0x04 || actionType == 0x05){
			if (typeof sessionId == 'string') sessionId = string_to_buffer(sessionId);
			//Writing sessionId length
			buffer[offset] = sessionId.length;
			offset++;
			//Writing sessionId
			for (var i = 0; i < sessionId.length; i++){
				buffer[offset + i] = sessionId[i];
			}
			offset += sessionId.length;
			//Writing a session expiration date, on session agreement request
			if (actionType == 0x04 && sessionExpiration){
				var sessionExpirationParts = splitUInt(sessionExpiration);
				writeUInt32BE(sessionExpirationParts.left, offset, buffer);
				offset += 4;
				writeUInt32BE(sessionExpirationParts.right, offset, buffer);
				offset += 4;
			}
		}

		return buffer;
	}

	function buildSessionPayload(username, sessionId){
		if (typeof username != 'string') throw new TypeError('username must be a string');
		if (username.length == 0 || username.length > 255) throw new TypeError('username must be a string ]0; 256[ bytes long');
		if (!((sessionId instanceof Uint8Array) || typeof sessionId == 'string')) throw new TypeError('sessionId must either be a string or a buffer');
		if (sessionId.length == 0 || sessionId.length > 255) throw new TypeError('sessionId must be a ]0; 256[ bytes long');

		/*
		* 1 version byte
		* 1 username length byte
		* 8 timestamp bytes
		* 1 sessionId length byte
		*/
		var minSize = 11;

		var payloadBuf = new Uint8Array(minSize + username.length + sessionId.length);
		var offset = 0;

		//Writing protocol version
		payloadBuf[offset] = 0x01;
		offset++;
		//Writing username length
		var usernameBuf = string_to_buffer(username);
		payloadBuf[offset] = usernameBuf.length;
		offset++;
		//Writing username
		for (var i = 0; i < usernameBuf.length; i++){
			payloadBuf[offset + i] = usernameBuf[i];
		}
		offset += usernameBuf.length;
		//Writing timestamp
		var timestamp = Math.floor(Date.now() / 1000);
		var timestampParts = splitUInt(timestamp);
		writeUInt32BE(timestampParts.left, offset, payloadBuf);
		offset += 4;
		writeUInt32BE(timestampParts.right, offset, payloadBuf);
		offset += 4;
		//Writing sessionId length
		if (typeof sessionId == 'string') sessionId = string_to_buffer(sessionId);
		payloadBuf[offset] = sessionId.length;
		offset++;
		//Writing sessionId
		for (var i = 0; i < sessionId.length; i++){
			payloadBuf[i + offset] = sessionId[i];
		}
		offset += sessionId.length;

		return to_base64(payloadBuf);
	}

	function randomBuffer(size){
		if (!(typeof size == 'number' && size > 0 && Math.floor(size) == size)) throw new TypeError('size must be a strictly positive integer');
		var b = new Uint8Array(size);
		window.crypto.getRandomValues(b);
		return b;
	}

	function isNullBuffer(b){
		if (!(b instanceof Uint8Array)) throw new TypeError('b must be an Uint8Array');
		for (var i = 0; i < b.length; i++) if (b[i] != 0) return false;
		return true;
	}

	function headersObject(h){
		if (typeof h == 'object') return h;
		else if (typeof h != 'string') throw new TypeError('invalid type for h: ' + typeof h);

		var hObject = {};
		var hArray = h.split(/\r\n/g);
		for (var i = 0; i < hArray.length; i++){
			var currentHeader = headerKeyVal(hArray[i]);
			if (!currentHeader){
				//if (console.warn) console.warn('Cannot parse header: ' + hArray[i]);
				continue;
			}
			hObject[currentHeader.key] = currentHeader.val;
		}
		return hObject;
	}

	function headerKeyVal(s){
		if (typeof s != 'string') throw new TypeError('s must be a string');

		var headerParts = s.split(/(: ?)/);
		if (headerParts.length < 3) return undefined;
		return {key: headerParts[0], val: headerParts.slice(2).join('')};
	}

	function splitUInt(n){
		if (!(typeof n == 'number' && Math.floor(n) == n && n >= 0)) throw new TypeError('n must be a positive integer');
		var l, r;
		r = n % TwoPower32;
		l = n - r;
		return {left: l, right: r};
	}

	function joinUInt(left, right){
		if (!(typeof left == 'number' && Math.floor(left) == left && left >= 0 && left < TwoPower32)) throw new TypeError('left must be an integer number within the range [0; 2^32-1]');
		if (!(typeof right == 'number' && Math.floor(right) == right && right >= 0 && right < TwoPower32)) throw new TypeError('right must be an integer number with the range [0; 2^32-1]');
		var n = 0;
		n += right;
		n += left * TwoPower32;
		return n;
	}

	function writeUInt32BE(val, offset, buffer){
		for (var i = 0; i < 4; i++){
			buffer[offset + i] = ( val >> (8 * (3 - i)) ) % 256;
		}
	}

	function defaultSignatureProvider(message, privateKey, callback){
		if (typeof callback != 'function') throw new TypeError('callback must be a function');
		if (!(privateKey instanceof Uint8Array)){
			callback(new Error('privateKey must be a Uint8Array'));
			return;
		}
		if (!(message instanceof Uint8Array)){
			callback(new Error('message must be a Uint8Array'));
			return;
		}
		var signature;
		try {
			signature = sodium.crypto_sign_detached(message, privateKey);
		} catch (e){
			callback(e);
			return;
		}
		callback(null, signature);
	}

	function defaultScryptProvider(args, callback){
		if (typeof callback != 'function') throw new TypeError('callback must be a function');
		if (!(Array.isArray(args) && args.length > 0)){
			callback(new Error('args must be a non-empty array'));
			return;
		}
		var derivedKey;
		try {
			derivedKey = sodium.crypto_pwhash_scryptsalsa208sha256_ll.apply(sodium, args);
		} catch (e){
			callback(e);
			return;
		}
		callback(null, derivedKey);
	}

	function clone(o){
		var typeO = typeof o;
		if (typeO == 'object'){
			if (Array.isArray(o)){
				var c = [];
				for (var i = 0; i < o.length; i++) c.push(clone(o[i]));
				return c;
			} else if (o instanceof Date){
				return new Date(o.getTime());
			} else if (o == null){
				return null;
			} else {
				var props = Object.keys(o);
				var c = {};
				for (var i = 0; i < props.length; i++) c[props[i]] = clone(o[props[i]])
				return c;
			}
		} else if (typeO == 'number' || typeO == 'string' || typeO == 'boolean') return o;
	}

	lib.supportedAlgorithms = supportedAlgorithms;
	lib.createIdentityKey = createKey;
	lib.scryptEncrypt = scryptEncrypt;
	lib.scryptDecrypt = scryptDecrypt;
	lib.loadKey = loadKey;
	lib.saveKey = saveKey;
	lib.buildPayload = buildPayload;
	lib.buildSessionPayload = buildSessionPayload;
	lib.Client = client;
	lib.defaultAgent = defaultAgent;
	lib._validateReqOptions = validateReqOptions;
	lib._headersObject = headersObject;

	return lib;
})();
