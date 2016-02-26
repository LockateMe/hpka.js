var assert = require('assert');
var ph = require('phantom');
var phOptions = [];

var phantom;
var testPage;

var serverSettings;

var testUsername = 'test';
var testPassword = 'password';
var testSessionId;

var absMaxForSessionTTL = 45 * 365.25 * 24 * 3600; //1/1/2015 00:00:00 UTC, in seconds. A threshold just helping us determine whether the provided wantedSessionExpiration is a TTL or a timestamp

function validStatusCode(n){
	if (!n) return;
	var v = typeof n == 'number' && Math.floor(n) == n && n >= 100 && n < 600;
	if (!v) throw new TypeError('when defined, _expectedStatusCode must be an integer number, with the [100..600[ range');
}

function validHPKAErrorCode(n){
	if (!n) return;
	var nCopy = n;
	if (typeof v == 'string') n = parseInt(n);
	if (isNaN(n)) throw new TypeError('Invalid number : ' + nCopy);
	var v = typeof n == 'number' && Math.floor(n) == n && n > 0 && n <= 16;
	if (!v) throw new TypeError('Invalid error code : ' + nCopy);
}

function isHPKAError(e){
	var errMessage;
	if (typeof errMessage == 'object') errMessage = e.message;
	else errMessage = e;

	return /^HPKA-Error: *\d+$/gi.test(errMessage);
}

function isString(s){
	return typeof s == 'string' && s.length > 0;
}

function isFunction(f){
	return typeof f == 'function';
}

function equalToOne(val, matchingArray){
	if (!(Array.isArray(matchingArray) && matchingArray.length > 0)) return val == matchingArray;
	for (var i = 0; i < matchingArray.length; i++) if (matchingArray[i] == val) return true;
	return false;
}

function performReq(reqOptions, body, callback){

	testPage.evaluate(function(reqOptions, body){
		return performReqSync(reqOptions, body);
	}, reqOptions, body)
	.then(function(resObj){
		callback(undefined, resObj.body, resObj);
	})
	.catch(function(err){
		console.error('Error on performReq: ' + err);
		process.exit(1);
	});
}

function waitForResult(cb){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	function getResult(){
		testPage.evaluate(function(){
			if (!cbResult) return;

			var r = cbResult;
			cbResult = null;
			return r;
		}).then(function(result){
			if (result) cb(result);
			else wait();
		}).catch(function(err){
			console.error('Error while waitForResult: ' + JSON.stringify(err));
			process.exit(1);
		});
	}

	function wait(){
		setTimeout(getResult, 50);
	}

	getResult();
}

exports.setServerSettings = function(_serverSettings){
	if (typeof _serverSettings != 'object') throw new TypeError('_serverSettings must be an object');

	serverSettings = _serverSettings;
};

exports.setup = function(allowGetSessions, cb){
	testPage.evaluate(function(){
		var argsArray = arguments.length === 1 ? [arguments[0]] : Array.apply(null, arguments);
		setupClient.apply(null, argsArray);
	}, testUsername, testPassword, allowGetSessions, serverSettings)
	.then(cb)
	.catch(function(err){
		console.error('Error while setting up the test client: ' + err);
		process.exit(1);
	});
};

exports.start = function(cb){
	if (cb && typeof cb != 'function') throw new TypeError('when defined, cb must be a function');

	if (phantom){
		if (cb) cb();
		return;
	}

	ph.create(phOptions).then(function(pInstance){
		phantom = pInstance;

		phantom.createPage()
			.then(function(_p){
				testPage = _p;

				testPage.open('http://' + serverSettings.host + ':' + serverSettings.port + '/unit.html').then(function(status){

					testPage.property('onConsoleMessage', function(msg, lineNum, sourceId) {
						console.log(msg + ' (from line #' + lineNum + ' in "' + sourceId + '")');
					});

					if (cb) cb();
				});
			})
			.catch(function(err){
				console.error('Create page err');
				console.error(err);
				process.exit(1);
			});
	})
	.catch(function(err){
		console.error('Create phantom err');
		console.error(err);
		process.exit(1);
	});
};

exports.stop = function(cb){
	if (cb && typeof cb != 'function') throw new TypeError('when defined, cb must be a function');

	if (!phantom){
		if (cb) cb();
		return;
	}

	phantom.exit();
	phantom = null;

	if (cb) cb();
};

exports.unauthenticatedReq = function(cb){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	performReq(serverSettings, undefined, function(err, body, res){
		if (err) throw err;
		assert.equal(res.statusCode, 200, 'On successful anonymous requests, status code must be 200');
		assert.equal(body, 'Anonymous user', 'Unexpected string from server: ' + body);
		cb();
	});
};

exports.registrationReq = function(cb, _expectedBody, _expectedStatusCode){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || ('Welcome ' + testUsername + ' !');
	var expectedStatusCode = _expectedStatusCode || 200;

	testPage.evaluate(function(serverSettings){
		testClient.registerAccount(serverSettings, function(err, statusCode, body){
			var r = {err: err, statusCode: statusCode, body: body};
			cbResult = r;
		});
	}, serverSettings)
	.then(function(){
		waitForResult(function(res){
			if (res.err && !isHPKAError(res.err)){
				console.error('Error on registrationReq: ' + res.err);
				process.exit(1);
			}

			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on registration: ' + res.statusCode);
			assert.equal(res.body, expectedBody, 'Unexpected message on registration: ' + res.body);
			cb();
		});
	})
	.catch(function(e){
		console.error('Error on registrationReq: ' + e);
		process.exit(1);
	});
};

exports.authenticatedReq = function(cb, withForm, strictMode, _expectedBody, _expectedSuccess){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a string');

	if (_expectedSuccess == null || typeof _expectedSuccess == 'undefined') _expectedSuccess = true; //If _expectedSuccess is omitted, set it to true

	var expectedBody = _expectedBody;
	if (_expectedSuccess){
		if (withForm){
			expectedBody = expectedBody || 'OK';
		} else {
			expectedBody = expectedBody || ('Authenticated as : ' + testUsername);
		}
	} else {
		if (strictMode){
			expectedBody = expectedBody || 'Invalid key';
		} else {
			expectedBody = expectedBody || 'Anonymous user';
		}
	}

	var expectedStatusCode;
	if (strictMode) expectedStatusCode = _expectedSuccess ? 200 : 445;
	else expectedStatusCode = 200;

	var expectedHPKAErrValue = '3';

	testPage.evaluate(function(serverSettings, withForm){
		var reqSettings;

		if (withForm){
			var fData = new FormData();
			fData.append('field-one', 'test');
			fData.append('field-two', 'test 2');

			reqSettings = {
				host: serverSettings.host,
				port: serverSettings.port,
				method: 'POST',
				path: serverSettings.path,
				headers: {
					'test': '1'
				},
				body: fData
			};
		} else {
			reqSettings = serverSettings;
		}

		testClient.request(reqSettings, function(err, statusCode, body){
			var r = {err: err, statusCode: statusCode, body: body};
			cbResult = r;
		});
	}, serverSettings, withForm)
	.then(function(){
		waitForResult(function(res){
			if (res.err && !isHPKAError(res.err)){
				console.error('Error on authenticatedReq:' + res.err);
				process.exit(1);
			}

			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on authenticated request: ' + res.statusCode);

			if (strictMode){
				assert.equal(res.body, expectedBody, 'Unexpected response body in authenticated request (strict-mode): ' + res.body);
				if (_expectedSuccess) assert.equal(res.err.toLowerCase().replace(/ +/g, ''), 'hpka-error:' + expectedHPKAErrValue, 'Unexpected HPKA error code: ' + res.err);
			} else {
				assert.equal(res.body, expectedBody, 'Unexpected response body in authenticated request (non-strict mode):' + res.body);
			}

			cb();
		});
	})
	.catch(function(err){
		console.error('Error on authenticatedReq: ' + e);
		process.exit(1);
	});
};

exports.deletionReq = function(cb, _expectedBody, _expectedStatusCode){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('When defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || (testUsername + ' has been deleted!');
	var expectedStatusCode = _expectedStatusCode || 200;

	testPage.evaluate(function(serverSettings){
		testClient.deleteAccount(serverSettings, function(err, statusCode, body){
			var r = {err: err, statusCode: statusCode, body: body};
			cbResult = r;
		});
	}, serverSettings)
	.then(function(){
		waitForResult(function(res){
			if (res.err && !isHPKAError(res.err)){
				console.error('Error while deleting user account : ' + res.err);
				process.exit(1);
			}

			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on account deletion request: ' + res.statusCode);
			assert.equal(res.body, expectedBody, 'Unexpected response body on account deletion request: ' + res.body);
			cb();
		});
	})
	.catch(function(e){
		console.error('Error while deleting user account : ' + e);
		process.exit(1);
	});
};

exports.keyRotationReq = function(cb, _expectedBody, _expectedStatusCode){
	/*if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || 'Keys have been rotated!';
	var expectedStatusCode = _expectedStatusCode || 200;

	testPage.evaluate(function(serverSettings){

	})
	.then(function(){
		waitForResult(function(res){
			if (res.err && !isHPKAError(res.err)){
				console.error(res.err);
				process.exit(1);
			}

			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on key rotation: ' + res.statusCode);
			assert.equal(res.body, expectedBody, 'Unexpected response body on key rotation: ' + body);

			cb();
		});
	})
	.catch(function(e){
		console.error('Error while rotating user keys : ' + e);
		process.exit(1);
	});*/
};

exports.sessionAgreementReq = function(cb, wantedSessionExpiration, _expectedBody, _expectedStatusCode, _expectedSessionExpiration){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || 'Session created';
	var expectedStatusCode = _expectedStatusCode || 200;
	var expectedSessionExpiration = _expectedSessionExpiration || wantedSessionExpiration || 0; //Server-import || user-defined || 0 (default, no TTL on session)

	if (expectedSessionExpiration && expectedSessionExpiration != 0 && expectedSessionExpiration < absMaxForSessionTTL){
		//The provided expectedSessionExpiration is a time-to-live (TTL), and not and expiration date
		expectedSessionExpiration += Math.floor(Date.now() / 1000);
	}

	testPage.evaluate(function(serverSettings, wantedSessionExpiration){

		var newSessionId = new Uint8Array(16);
		window.crypto.getRandomValues(newSessionId);

		testClient.createSession(serverSettings, newSessionId, wantedSessionExpiration, function(err, statusCode, body, headers, sessionExpiration){
			var r = {
				err: err,
				statusCode: statusCode,
				body: body,
				headers: headers,
				sessionExpiration: sessionExpiration,
				sessionId: sodium.to_hex(newSessionId)
			};
			cbResult = r;
		});

	}, serverSettings, wantedSessionExpiration)
	.then(function(){
		waitForResult(function(res){
			if (res.err && !isHPKAError(res.err)){
				console.error('Error on SessionID agreement: ' + res.err);
				process.exit(1);
			}

			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on session agreement: ' + res.statusCode);

			var currentSessionExpiration = res.sessionExpiration;
			if (expectedSessionExpiration != 0){
				var upperExpirationWindow = expectedSessionExpiration + 5,
					lowerExpirationWindow = expectedSessionExpiration - 5;
				assert(currentSessionExpiration >= lowerExpirationWindow && currentSessionExpiration <= upperExpirationWindow, 'Unexpected session expiration: ' + currentSessionExpiration + '; expected session expiration: ' + expectedSessionExpiration);
			} else {
				assert(currentSessionExpiration == 0, 'Unexpected non-null session expiration: ' + currentSessionExpiration);
			}

			assert.equal(res.body, expectedBody, 'Unexpected response body on session agreement: ' + res.body);

			testSessionId = res.sessionId;

			cb();
		});
	})
	.catch(function(e){
		console.error('Error on SessionID agreement: ' + JSON.stringify(e));
		process.exit(1);
	});
};

exports.sessionRevocationReq = function(cb, _expectedBody, _expectedStatusCode){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || 'SessionId revoked';
	var expectedStatusCode = _expectedStatusCode || 200;

	testPage.evaluate(function(serverSettings, sessionId){
		testClient.revokeSession(serverSettings, sodium.from_hex(sessionId), function(err, statusCode, body, headers){
			var r = {
				err: err,
				statusCode: statusCode,
				body: body,
				headers: headers
			};
			cbResult = r;
		});
	}, serverSettings, testSessionId)
	.then(function(){
		waitForResult(function(res){
			if (res.err && !isHPKAError(res.err)){
				console.error('Error on session revocation: ' + res.err);
				process.exit(1);
			}

			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on session revocation: ' + res.statusCode);
			assert.equal(res.body, expectedBody, 'Unexpected response body on session revocation: ' + res.body);

			cb();
		});
	})
	.catch(function(e){
		console.error('Error on session revocation: ' + e);
		process.exit(1);
	});
};

exports.sessionAuthenticatedReq = function(cb, strictMode, _expectedBody, _expectedSuccess, _usingSessionId){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	var expectedBody = _expectedBody;

	if (_expectedSuccess == null || typeof _expectedSuccess == 'undefined') _expectedSuccess = true; //If _expectedSuccess is omitted, set it to true

	if (_expectedSuccess){
		expectedBody = expectedBody || ('Authenticated as : ' + testUsername);
	} else {
		if (strictMode){
			expectedBody = expectedBody || 'Invalid token';
		} else {
			expectedBody = expectedBody || 'Anonymous user';
		}
	}

	var expectedStatusCode;
	if (strictMode) expectedStatusCode = _expectedSuccess ? 200 : 445; //In strict mode, if the authentication fails a 445 status code is returned
	else expectedStatusCode = 200;

	var expectedHPKAErrValue = '2';

	var sId = _usingSessionId || testSessionId;

	testPage.evaluate(function(serverSettings, sId){
		var sessionPayloadStr = hpka.buildSessionPayload(testUsername, sodium.from_hex(sId));

		if (serverSettings.headers) serverSettings.headers['HPKA-Session'] = sessionPayloadStr;
		else serverSettings.headers = {'HPKA-Session': sessionPayloadStr};

		hpka.defaultAgent(serverSettings, function(err, statusCode, body, headers){
			var r = {
				err: err,
				statusCode: statusCode,
				body: body,
				headers: headers
			};
			cbResult = r;
		});

	}, serverSettings, sId)
	.then(function(){
		waitForResult(function(res){
			if (res.err && !isHPKAError(res.err)){
				console.error('Error on session-authenticated request: ' + err);
				process.exit(1);
			}

			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on session-authenticated request: ' + res.statusCode);

			if (strictMode){
				assert.equal(res.body, expectedBody, 'Unexpected response body on session-authenticated request (strict-mode): ' + res.body);
				if (!_expectedSuccess){
					console.error('Received headers on expected failure: ' + JSON.stringify(res.headers));
					assert.equal(res.headers['hpka-error'] || res.headers['HPKA-Error'], expectedHPKAErrValue, 'Unexpected HPKA error code: ' + (res.headers['hpka-error'] || res.headers['HPKA-Error']));
				}
			} else {
				assert.equal(res.body, expectedBody, 'Unexpected response body on session-authenticated request (non strict-mode): ' + res.body);
			}

			cb();
		});
	})
	.catch(function(err){
		console.error('Error on session-authenticated request: ' + err);
		process.exit(1);
	});
};

exports.getUserSessions = function(){

};

exports.setUserSessions = function(_s, merge){

};
