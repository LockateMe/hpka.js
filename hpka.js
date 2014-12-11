var hpka = (function(){
	var lib = {};

	if (!libsodium) throw new Error('libsodium is missing!');

	var is_hex = libsodium.is_hex;
	var from_hex = libsodium.from_hex;
	var to_hex = libsodium.to_hex;

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
		if (is_hex(publicKeyParam)){
			decodedKeyPair.publicKey = libsodium.from_hex(publicKeyParam);
		} else if (publicKeyParam instanceof Uint8Array){
			decodedKeyPair.publicKey = publicKeyParam;
		} else throw new TypeError('Invalid public key format. Must either be a Uint8Array or a hex-string');

		var privateKeyParam = keyPair.privateKey || keyPair.secretKey;
		if (is_hex(privateKeyParam)){
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

	/* Encrypted buffer format. Numbers are in big endian
    * 2 bytes : r (unsigned short)
    * 2 bytes : p (unsigned short)
    * 8 bytes : opsLimit (unsigned long)
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

		var r = 8, p = 1, opsLimit = 16384; //Scrypt parameters
		var saltSize = 8;
		var nonceSize = libsodium.crypto_secretbox_noncebytes;
		var totalSize = 16 + saltSize + nonceSize + buffer.length + libsodium.crypto_secretbox_macbytes;

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
		for (var i = 8; i > 0; i--){
			b[ bIndex ] = (opsLimit >> (8 * (i - 1)));
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
		//Writing keyBuffer size
		var encContentSize = buffer.length + libsodium.crypto_secretbox_macbytes;
		b[bIndex] = (encContentSize >> 24);
		b[bIndex+1] = (encContentSize >> 16);
		b[bIndex+2] = (encContentSize >> 8);
		b[bIndex+3] = encContentSize;
		bIndex += 4;
		//Writing salt
		var salt = randomBuffer(saltSize);
		for (var i = 0; i < saltSize; i++){
			b[ bIndex + i ] = salt[i];
		}
		bIndex += saltSize;
		//Writing nonce
		var nonce = randomBuffer(nonceSize);
		for (var i = 0; i < nonceSize; i++){
			b[ bIndex + i ] = nonce[i];
		}
		bIndex += nonceSize;

		//Derive password into encryption key
		var encKeyLength = libsodium.crypto_secretbox_keybytes;
		var encKey = libsodium.crypto_pwhash_scryptsalsa208sha256(password, salt, opsLimit, r, p, encKeyLength);
		//Encrypt the content and write it
		var cipher = libsodium.crypto_secretbox_easy(buffer, nonce, encKey);
		for (var i = 0; i < cipher.length; i++){
			b[bIndex+i] = cipher[i];
		}
		bIndex += cipher.length;

		return b;
	}

	function scryptDecrypt(buffer, password){
		if (!(buffer && buffer instanceof Uint8Array)) throw new TypeError('Buffer must be a Uint8Array');
		if (!(typeof password == 'string' || passowrd instanceof Uint8Array)) throw new TypeError('password must be a string or a Uint8Array buffer');
		var minRemainingSize = 16 + libsodium.crypto_secretbox_macbytes; //16 bytes from the above format description + 4 for the MAC appended to the ciphertext

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
		for (var i = 7; i >= 0; i--){
			opsLimit += (buffer[rIndex] << (8*i));
			rIndex++;
		}
		minRemainingSize -= 8;

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

		if (in_avail() < minRemainingSize) throw new RangeError('Invalid encrypted buffer format');

		if (nonceSize != libsodium.crypto_secretbox_noncebytes) throw new RangeError('Invalid nonce size');

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

		//Reading nonce
		var nonce = new Uint8Array(nonceSize);
		for (var i = 0; i < nonceSize; i++){
			nonce[i] = buffer[rIndex+i];
		}
		rIndex += nonceSize;
		minRemainingSize -= nonceSize;

		//Deriving password into encryption key
		var encKeyLength = libsodium.crypto_secretbox_keybytes;
		var encKey = libsodium.crypto_pwhash_scryptsalsa208sha256(password, salt, opsLimit, r, p, encKeyLength);

		var cipherText = new Uint8Array(encBufferSize);
		for (var i = 0; i < encBufferSize; i++){
			cipherText[i] = buffer[rIndex+i];
		}
		rIndex += encBufferSize;
		minRemainingSize -= encBufferSize;

		//Decrypting the ciphertext
		var plainText = libsodium.crypto_secretbox_open_easy(cipherText, encKey, nonce);
		return plainText; //If returned result is undefined, then invalid password (or corrupted buffer)

		function in_avail(){return buffer.length - rIndex;}

	}

	function loadKey(keyBuffer, password){
		if (!((typeof keyBuffer == 'string' && is_hex(keyBuffer)) || keyBuffer instanceof Uint8Array)) throw new TypeError('keyBuffer must either be a hex-string or a buffer');
		if (!(password && (typeof password == 'string' || password instanceof Uint8Array))) throw new TypeError('password must either be a string or a buffer');
	}

	function saveKey(keyPair, password){
		if (typeof keyPair != 'object') throw new TypeError('');
		if (!(typeof password == 'string' || password instanceof Uint8Array)) throw new TypeError('password must either be a string or a Uint8Array buffer');
		var decodedKeyPair = {};

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

		
	}

	function buildPayload(keyPair, username, userAction, httpMethod, hostAndPath){
		if (typeof keyPair != 'object') throw new TypeError('keyPair must be an object');
		if (!(typeof username == 'string' && username.length > 0)) throw new TypeError('Username must be a string');
		if (!(typeof userAction == 'number' && userAction == Math.floor(userAction) && userAction >= 0 && userAction <= 3)) throw new TypeError('userAction must a byte between 0 and 3');
		var vId = getVerbId(httpMethod);
		if (!vId) throw new TypeError('Invalid HTTP method');

		var decodedKeyPair;

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

		if (decodedKeyPair.publicKey.length != libsodium.crypto_sign_publickeybytes) throw new TypeError('Invalid public key size');
		if (decodedKeyPair.privateKey.length != libsodium.crypto_sign_secretkeybytes) throw new TypeError('Invalid private key size');

		var usernameBuffer = libsodium.utf8_decode(username);
		if (usernameBuffer.length > 255) throw new TypeError('Username cannot be more than 255 bytes long');

		var hpkaReqBuffer = buildPayloadWithoutSignature(decodedKeyPair, usernameBuffer, userAction);

		var hostAndPathBuf = libsodium.utf8_decode(hostAndPath);
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
		var hpkaSignature = libsodium.crypto_sign_detached(signedBlob, decodedKeyPair.privateKey);
		return {'req': base64EncArr(hpkaReqBuffer), 'sig': base64EncArr(hpkaSignature)};
	}
	lib.buildPayload = buildPayload;

	function buildPayloadWithoutSignature(keyPair, username, userAction){
		var bufferLength = 0;
		bufferLength += 1; //Protocol version byte
		bufferLength += 8; //Timestamp bytes
		bufferLength += 1; //Username length byte
		bufferLength += username.length; //Reserving bytes for username
		bufferLength += 1; //HPKA actionType
		bufferLength += 1; //KeyType

		bufferLength += 2; //Public key length field
		bufferLength += libsodium.crypto_sign_publickeybytes;

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
		buffer[offset] = libsodium.crypto_sign_publickeybytes >> 8;
		buffer[offset+1] = libsodium.crypto_sign_publickeybytes;
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

	/**
	* Base64 <-> Uint8Array conversion tools.
	* Harvested from MDN:
	* https://developer.mozilla.org/en-US/docs/Web/JavaScript/Base64_encoding_and_decoding
	*/
	function b64ToUint6 (nChr) {

		return nChr > 64 && nChr < 91 ?
			nChr - 65
			: nChr > 96 && nChr < 123 ?
			nChr - 71
			: nChr > 47 && nChr < 58 ?
			nChr + 4
			: nChr === 43 ?
			62
			: nChr === 47 ?
			63
			:
			0;

	}

	function base64DecToArr (sBase64, nBlocksSize) {

		var
			sB64Enc = sBase64.replace(/[^A-Za-z0-9\+\/]/g, ""), nInLen = sB64Enc.length,
			nOutLen = nBlocksSize ? Math.ceil((nInLen * 3 + 1 >> 2) / nBlocksSize) * nBlocksSize : nInLen * 3 + 1 >> 2, taBytes = new Uint8Array(nOutLen);

		for (var nMod3, nMod4, nUint24 = 0, nOutIdx = 0, nInIdx = 0; nInIdx < nInLen; nInIdx++) {
			nMod4 = nInIdx & 3;
			nUint24 |= b64ToUint6(sB64Enc.charCodeAt(nInIdx)) << 18 - 6 * nMod4;
			if (nMod4 === 3 || nInLen - nInIdx === 1) {
			for (nMod3 = 0; nMod3 < 3 && nOutIdx < nOutLen; nMod3++, nOutIdx++) {
				taBytes[nOutIdx] = nUint24 >>> (16 >>> nMod3 & 24) & 255;
			}
			nUint24 = 0;

			}
		}

		return taBytes;
	}

	/* Base64 string to array encoding */

	function uint6ToB64 (nUint6) {

		return nUint6 < 26 ?
			nUint6 + 65
			: nUint6 < 52 ?
			nUint6 + 71
			: nUint6 < 62 ?
			nUint6 - 4
			: nUint6 === 62 ?
			43
			: nUint6 === 63 ?
			47
			:
			65;

	}

	function base64EncArr (aBytes) {

		var nMod3 = 2, sB64Enc = "";

		for (var nLen = aBytes.length, nUint24 = 0, nIdx = 0; nIdx < nLen; nIdx++) {
			nMod3 = nIdx % 3;
			if (nIdx > 0 && (nIdx * 4 / 3) % 76 === 0) { sB64Enc += "\r\n"; }
			nUint24 |= aBytes[nIdx] << (16 >>> nMod3 & 24);
			if (nMod3 === 2 || aBytes.length - nIdx === 1) {
			sB64Enc += String.fromCharCode(uint6ToB64(nUint24 >>> 18 & 63), uint6ToB64(nUint24 >>> 12 & 63), uint6ToB64(nUint24 >>> 6 & 63), uint6ToB64(nUint24 & 63));
			nUint24 = 0;
			}
		}

		return sB64Enc.substr(0, sB64Enc.length - 2 + nMod3) + (nMod3 === 2 ? '' : nMod3 === 1 ? '=' : '==');

	}

	var base64 = {
		Uint8ArrayToBase64: base64EncArr,
		to_base64: base64EncArr,
		Base64ToUint8Array: base64DecToArr,
		from_base64: base64DecToArr
	};

	lib.base64 = base64;


	return lib;
})();
