//Copied from test.js in node-hpka

var http = require('http');
var hpka = require('hpka');
var fs = require('fs');
var path = require('path');
var mime = require('mime');
var express = require('express');
var bodyParser = require('body-parser');

//In-memory list of registered users and sessions
var userList = {};
var sessions = {};

var httpPort = 2500;
var maxSessionsLife = 7 * 24 * 3600;

var yell = false;

var server;
var hpkaMiddleware;
var applicationToUse;

function log(m){
	if (yell) console.log(m);
}

function writeRes(res, body, headers, statusCode){
	headers = headers || {};
	var bodyLength;

	if (typeof body == 'object' && !Buffer.isBuffer(body)){
		body = JSON.stringify(body);
		headers['Content-Type'] = 'application/json';
	}
	if (Buffer.isBuffer(body)){
		bodyLength = Buffer.byteLength(body);
	} else { //Assuming string
		bodyLength = body.length;
	}

	headers['Content-Length'] = bodyLength;

	res.writeHead(statusCode || 200, headers);
	res.write(body);
	res.end();
}

function writeHpkaErr(res, message, errorCode){
	writeRes(res, message, {'HPKA-Error': errorCode}, 445);
}


var getHandler = function(req, res){
	var headers = {'Content-Type': 'text/plain'};
	var body;
	if (req.username){
		//console.log(req.method + ' ' + req.url + ' authenticated request by ' + req.username);
		body = 'Authenticated as : ' + req.username;
		//Manual signature verification
		var hpkaReq = req.headers['hpka-req'];
		var hpkaSig = req.headers['hpka-signature'];
		var method = req.method;
		var reqUrl = 'http://' + (req.headers.hostname || req.headers.host) + req.url
		//console.log('HpkaReq: ' + hpkaReq + '; HpkaSig: ' + hpkaSig + '; ' + method + '; reqUrl: ' + reqUrl);
		if (hpkaReq && hpkaSig){
			hpka.verifySignature(hpkaReq, hpkaSig, reqUrl, method, function(err, isValid, username, hpkaReq){
				if (err) console.error('Error in hpkaReq: ' + err);
				if (!isValid) console.log('External validation failed');
				//else console.log('External validation success: ' + username + ': ' + JSON.stringify(hpkaReq));
			});
		}
	} else {
		//console.log(req.method + ' ' + req.url + ' anonymous request');
		body = 'Anonymous user';
	}

	writeRes(res, body, headers, 200);
};

var postHandler = function(req, res){
	if (req.body && Object.keys(req.body).length > 0){
		//console.log('Testing req values');
		assert.equal(req.body['field-one'], 'test', 'Unexpected form content');
		assert.equal(req.body['field-two'], 'test 2', 'Unexpected form content');
		assert.equal(req.headers.test, '1', 'Unexpected value the "test" header');
	}
	//console.log('Received form data: ' + JSON.stringify(req.body));
	//console.log('"test" header value: ' + req.headers.test);
	if (req.username){
		res.send(200, 'OK');
	} else {
		res.send(401, 'Not authenticated');
	}
};

var loginCheck = function(HPKAReq, req, res, callback){
	if (userList[HPKAReq.username] && typeof userList[HPKAReq.username] == 'object' && HPKAReq.checkPublicKeyEqualityWith(userList[HPKAReq.username])){
		callback(true);
		console.log('Authenticated request');
	} else callback(false);
};

var registration = function(HPKAReq, req, res){
	var username = HPKAReq.username;
	var keyInfo = HPKAReq.getPublicKey();
	userList[username] = keyInfo;
	console.log('User registration');
	var body = 'Welcome ' + username + ' !';
	res.writeHead(200, {'Content-Type': 'text/plain', 'Content-Length': body.length});
	res.write(body);
	res.end();
};

var deletion = function(HPKAReq, req, res){
	if (typeof userList[HPKAReq.username] != 'object') return;
	if (!HPKAReq.checkPublicKeyEqualityWith(userList[HPKAReq.username])){
		writeHpkaErr(res, 'Invalid user key', 3);
		return;
	}
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
		if (HPKAReq.checkPublicKeyEqualityWith(userList[HPKAReq.username])){
			//Replace the actual ke by the new key
			userList[HPKAReq.username] = newKeyReq.getPublicKey();
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

var sessionCheck = function(SessionReq, req, res, callback){
	var username = SessionReq.username;
	var sessionId = SessionReq.sessionId;

	if (!sessions[username]){
		callback(false);
		return;
	}

	var validId = false;
	for (var i = 0; i < sessions[username].length; i++){
		if (sessions[username][i] == sessionId){
			validId = true;
			break;
		}
	}

	callback(validId);
};

var sessionAgreement = function(HPKAReq, req, callback){
	var username = HPKAReq.username;
	var sessionId = HPKAReq.sessionId;
	//Expiration date agreement
	var finalSessionExpiration;
	var n = Math.floor(Date.now() / 1000);
	var currentMaxExpiration = maxSessionsLife + n;
	//User-provided expiration date for the sessionId
	var userSetExpiration = HPKAReq.sessionExpiration || 0;
	if (maxSessionsLife == 0){ //If the server doesn't impose a TTL, take the user-provided value as TTL
		finalSessionExpiration = userSetExpiration;
	} else if (userSetExpiration == 0 || userSetExpiration > currentMaxExpiration){ //Server-set TTL. Enforce lifespan
		finalSessionExpiration = currentMaxExpiration;
	} else {
		finalSessionExpiration = userSetExpiration;
	}
	//Check keys
	if (HPKAReq.checkPublicKeyEqualityWith(userList[username])){
		//Accept a sessionId
		if (sessions[username]){
			//Save the sessionId in the existing array
			//But before that, check that it's not already in the array
			var alreadyAgreed = false;
			for (var i = 0; i < sessions[username].length; i++) if (sessions[username][i] == sessionId){
				alreadyAgreed = true;
				break;
			}
			if (!alreadyAgreed) sessions[username].push(sessionId);
		} else {
			sessions[username] = [sessionId];
		}
		callback(true, finalSessionExpiration);
	} else callback(false);
};

var sessionRevocation = function(HPKAReq, req, callback){
	var username = HPKAReq.username;
	var sessionId = HPKAReq.sessionId;
	//Check keys
	if (HPKAReq.checkPublicKeyEqualityWith(userList[username])){
		//Revoke sessionId
		var currentSessionList = sessions[username];
		if (currentSessionList){
			if (currentSessionList.length == 0) sessions[username] = null;
			else {
				//Check that the sessionId is in the array and remove it
				for (var i = 0; i < currentSessionList.length; i++){
					if (currentSessionList[i] == sessionId){
						currentSessionList.splice(i, 1);
						break;
					}
				}
			}
		}
		callback(true);
	} else callback(false);
};

exports.setup = function(strictMode, disallowSessions){
	if (disallowSessions){
		hpkaMiddleware = hpka.expressMiddleware(loginCheck, registration, deletion, keyRotation, strictMode);
	} else {
		hpkaMiddleware = hpka.expressMiddleware(loginCheck, registration, deletion, keyRotation, strictMode, sessionCheck, sessionAgreement, sessionRevocation);
	}

	var app = express();
	app.use(bodyParser.json());
	app.use(bodyParser.urlencoded());
	app.use('/', express.static(__dirname));

	app.use(hpkaMiddleware);

	app.get('/', getHandler);
	app.post('/', postHandler);

	applicationToUse = app;
};

exports.clear = function(){
	userList = {};
	sessions = {};
};

exports.start = function(cb){
	if (cb && typeof cb != 'function') throw new TypeError('when defined, cb must be a function');
	if (!hpkaMiddleware) throw new TypeError('server not yet set up');

	server = http.createServer(applicationToUse);
	server.listen(serverPort, function(){
		if (cb) cb();
	});
};

exports.stop = function(cb){
	if (cb && typeof cb != 'function') throw new TypeError('when defined, cb must be a function');

	if (!server){
		if (cb) cb();
		return;
	}

	server.close(function(){
		server = undefined;
		if (cb) cb();
	});
};

exports.getServerPort = function(){
	return serverPort;
};

exports.setServerPort = function(p){
	if (!(typeof p == 'number' && p > 0 && p < 65536 && p == Math.floor(p))) throw new TypeError('p must be an integer number, in the [1-65535] range');
	serverPort = p;
};

exports.getMaxSessionLife = function(){
	return maxSessionsLife;
};

exports.setMaxSessionLife = function(ttl){
	if (!(typeof ttl == 'number' && ttl > 0 && ttl == Math.floor(ttl))) throw new TypeError('n must be a positive integer number');
};

expors.setYell = function(_y){
	yell = _y;
};

/*
console.log('Starting the server');
var server = http.createServer(hpka.httpMiddleware(requestHandler, loginCheck, registration, deletion, keyRotation, true));
server.listen(httpPort, function(){
	console.log('Server started on port ' + httpPort);
});
*/
