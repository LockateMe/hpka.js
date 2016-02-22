var assert = require('assert');
var ph = require('phantom');
var phOptions = [];

var phantom;
var testPage;

var serverSettings;

var testUsername = 'test';
var testPassword = 'password';
var testSessionId;

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

/*function runInBrowser(func, args, cb){
	if (!testPage) throw new TypeError('testPage is not yet initialized');
	var evalArgs = [func, cb];
	for (var i = 0; i < args.length; i++) evalArgs.push(args[i]);
	testPage.evaluate.apply(this, evalArgs);
}*/

function performReq(reqOptions, body, callback){

	testPage.evaluate(function(reqOptions, body){
		return performReqSync(reqOptions, body);
	}, function(resObj){
		callback(undefined, resObj.body, resObj);
	}, reqOptions, body);
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

				/*testPage.property('onConsoleMessage', function(m, msgLine){
					log('Page message: ' + m);
				});*/

				testPage.open('http://' + serverSettings.hostname + ':' + serverSettings.port + '/unit.html').then(function(status){

					testPage.property('onConsoleMessage', function(msg, lineNum, sourceId) {
						log('CONSOLE: ' + msg + ' (from line #' + lineNum + ' in "' + sourceId + '")');
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

	var expectedBody = _expectedBody || ('Welcome ' + testUsername + '!');
	var expectedStatusCode = _expectedStatusCode || 200;

	testPage.evaluate(function(serverSettings){
		testClient.registerUser(serverSettings, function(err, statusCode, body){
			var r = {err: err, statusCode: statusCode, body: body};
			cbResult = r;
		});
	}, serverSettings)
	.then(function(){
		waitForResult(function(res){
			if (res.err && !isHPKAError(res.err)){
				throw res.err;
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

	/*runInBrowser(function(serverSettings){
		testClient.registerUser(serverSettings, function(err, statusCode, body){
			var r = {err: err, statusCode: statusCode, body: body};
			cbResult = r;
		});
	}, [serverSettings], function(){
		waitForResult(function(res){
			if (res.err && !isHPKAError(res.err)){
				throw res.err;
			}

			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on registration: ' + res.statusCode);
			assert.equal(res.body, expectedBody, 'Unexpected message on registration: ' + res.body);
			cb();
		});
	})*/
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
				hostname: serverSettings.hostname,
				host: serverSettings.host,
				port: serverSettings.port,
				method: 'POST',
				path: serverSettings.path,
				headers: {
					'test': 1
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
				throw res.err;
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

	/*runInBrowser(function(serverSettings, withForm){
		var reqSettings;

		if (withForm){
			var fData = new FormData();
			fData.append('field-one', 'test');
			fData.append('field-two', 'test 2');

			reqSettings = {
				hostname: serverSettings.hostname,
				host: serverSettings.host,
				port: serverSettings.port,
				method: 'POST',
				path: serverSettings.path,
				headers: {
					'test': 1
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
	}, [serverSettings, withForm], function(){
		waitForResult(function(res){
			if (res.err && !isHPKAError(res.err)){
				throw res.err;
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
	});*/
};

exports.deletionReq = function(cb, _expectedBody, _expectedStatusCode){

};

exports.keyRotationReq = function(cb, newKeyPath, _expectedBody, _expectedStatusCode){

};

exports.sessionAgreementReq = function(cb, wantedSessionExpiration, _expectedBody, _expectedStatusCode, _expectedSessionExpiration){

};

exports.sessionRevocationReq = function(cb, _expectedBody, _expectedStatusCode){

};

exports.sessionAuthenticatedReq = function(cb, strictMode, _expectedBody, _expectedSuccess, _usingSessionId){

};

exports.getUserSessions = function(){

};

exports.setUserSessions = function(_s, merge){

};