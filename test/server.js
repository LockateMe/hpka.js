//Copied from test.js in node-hpka

var http = require('http');
var hpka = require('hpka');
var fs = require('fs');
var path = require('path');
var mime = require('mime');

//In-memory list of registered users
var userList = {};

//Getting the PKA info from a HPKAReq object
function getPubKeyObject(HPKAReq){
	//Checking that HPKAReq object is correctly formed
	var reqObj = {};
	if (!HPKAReq.keyType) throw new TypeError('Invalid HPKAReq obejct on getPubKeyObject method');
	reqObj.keyType = HPKAReq.keyType;
	if (HPKAReq.keyType == 'ecdsa'){ //ECDSA case
		if (!(HPKAReq.curveName && HPKAReq.point && HPKAReq.point.x && HPKAReq.point.y)) throw new TypeError('Malformed ECDSA request');
		reqObj.curveName = HPKAReq.curveName;
		reqObj.point = HPKAReq.point;
	} else if (HPKAReq.keyType == 'rsa'){ //RSA case
		if (!(HPKAReq.modulus && HPKAReq.publicExponent)) throw new TypeError('Malformed RSA request');
		reqObj.modulus = HPKAReq.modulus;
		reqObj.publicExponent = HPKAReq.publicExponent;
	} else if (HPKAReq.keyType == 'dsa'){ //DSA case
		if (!(HPKAReq.primeField && HPKAReq.divider && HPKAReq.base && HPKAReq.publicElement)) throw new TypeError('Malformed DSA request');
		reqObj.primeField = HPKAReq.primeField;
		reqObj.divider = HPKAReq.divider;
		reqObj.base = HPKAReq.base;
		reqObj.publicElement = HPKAReq.publicElement;
	} else if (HPKAReq.keyType == 'ed25519'){
		if (!(HPKAReq.publicKey)) throw new TypeError('Malformed Ed25519 request');
		reqObj.publicKey = HPKAReq.publicKey;
	} else throw new TypeError('Invalid key type : ' + HPKAReq.keyType);
	return reqObj;
}

function checkPubKeyObjects(pubKey1, pubKey2){
	if (!(typeof pubKey1 == 'object' && typeof pubKey2 == 'object')) throw new TypeError('Parameters must be objects');
	if (pubKey1.keyType != pubKey2.keyType) return false;
	if (pubKey1.keyType == "ecdsa"){
		//console.log('Common type : ecdsa');
		if (pubKey1.curveName != pubKey2.curveName) return false;
		if (pubKey1.point.x != pubKey2.point.x) return false;
		if (pubKey1.point.y != pubKey2.point.y) return false;
	} else if (pubKey1.keyType == "rsa"){
		//console.log('Common type : rsa');
		if (pubKey1.modulus != pubKey2.modulus) return false;
		if (pubKey1.publicExponent != pubKey2.publicExponent) return false;
	} else if (pubKey1.keyType == "dsa"){
		//console.log('Common type : dsa');
		if (pubKey1.primeField != pubKey2.primeField) return false;
		if (pubKey1.divider != pubKey2.divider) return false;
		if (pubKey1.base != pubKey2.base) return false;
		if (pubKey1.publicElement != pubKey2.publicElement) return false;
	} else if (pubKey1.keyType == 'ed25519'){
		//console.log('Common type : ed25519');
		if (pubKey1.publicKey != pubKey2.publicKey) return false;
	} else throw new TypeError('Invalid keyType');
	return true;
}

var requestHandler = function(req, res){
	var headers = {'Content-Type': 'text/plain'};
	var body;
	if (req.url == '/'){
		if (req.username){
			//console.log(req.method + ' ' + req.url + ' authenticated request by ' + req.username);
			body = 'Authenticated as : ' + req.username;
			//Manual signature verification
			var hpkaReq = req.headers['hpka-req'];
			var hpkaSig = req.headers['hpka-signature'];
			var method = req.method;
			var reqUrl = 'http://' + (req.headers.hostname || req.headers.host) + req.url
			//console.log('HpkaReq: ' + hpkaReq + '; HpkaSig: ' + hpkaSig + '; ' + method + '; reqUrl: ' + reqUrl);
			hpka.verifySignature(hpkaReq, hpkaSig, reqUrl, method, function(isValid, username, hpkaReq){
				if (!isValid) console.log('External validation failed');
				//else console.log('External validation success: ' + username + ': ' + JSON.stringify(hpkaReq));
			});
		} else {
			//console.log(req.method + ' ' + req.url + ' anonymous request');
			body = 'Anonymous user';
		}
		headers['Content-Length'] = body.length;
		res.writeHead(200, headers);
		res.write(body);
		res.end();
	} else {
		var filePath = path.join(__dirname, req.url.substring(1));
		console.log('File requested: ' + filePath);
		if (!fs.existsSync(filePath)){
			res.writeHead(404);
			res.write('Not found');
			res.end();
			return;
		}
		var fileStat = fs.statSync(filePath);
		var headers = {'Content-Type': mime.lookup(filePath), 'Content-Length': fileStat.size};
		res.writeHead(200, headers);
		fs.readFile(filePath, function(err, data){
			if (err) throw err;
			res.write(data);
			res.end();
		});
	}
};

var loginCheck = function(HPKAReq, req, res, callback){
	if (userList[HPKAReq.username] && typeof userList[HPKAReq.username] == 'object' && checkPubKeyObjects(getPubKeyObject(HPKAReq), userList[HPKAReq.username])){
		callback(true);
		console.log('Authenticated request');
	} else callback(false);
};

var registration = function(HPKAReq, req, res){
	var username = HPKAReq.username;
	var keyInfo = getPubKeyObject(HPKAReq);
	userList[username] = keyInfo;
	console.log('User registration');
	var body = 'Welcome ' + username + ' !';
	res.writeHead(200, {'Content-Type': 'text/plain', 'Content-Length': body.length});
	res.write(body);
	res.end();
};

var deletion = function(HPKAReq, req, res){
	if (typeof userList[HPKAReq.username] != 'object') return;
	userList[HPKAReq.username] = undefined;
	var headers = {'Content-Type': 'text/plain'};
	var body = HPKAReq.username + ' has been deleted!';
	console.log('User deletion');
	headers['Content-Length'] = body.length;
	res.writeHead(200, headers);
	res.write(body);
	res.end();
};

var keyRotation = function(HPKAReq, newKeyReq, req, res){
	var headers = {'Content-Type': 'text/plain'};
	var body;
	var errorCode;
	//Check that the username exists
	if (typeof userList[HPKAReq.username] != 'object'){
		body = 'Unregistered user';
		errorCode = 445;
		headers['HPKA-Error'] = 4;
	} else {
		//Check that the actual key is correct
		if (checkPubKeyObjects(userList[HPKAReq.username], getPubKeyObject(HPKAReq))){
			//Replace the actual ke by the new key
			userList[HPKAReq.username] = getPubKeyObject(newKeyReq);
			body = 'Keys have been rotated!';
		} else {
			body = 'Invalid public key'
			errorCode = 445;
			headers['HPKA-Error'] = 3;
		}
	}
	headers['Content-Length'] = body.length;
	res.writeHead(errorCode || 200, headers);
	res.write(body);
	res.end();
};

var httpPort = 2500;

console.log('Starting the server');
var server = http.createServer(hpka.httpMiddleware(requestHandler, loginCheck, registration, deletion, keyRotation, true));
server.listen(httpPort, function(){
	console.log('Server started on port ' + httpPort);
});
