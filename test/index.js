var testServer = require('./server');
var testClient = require('./client');

var cbLoc = '#cbhere#';
var yell = false;

var serverSettings = {
	hostname: 'localhost',
	port: 2500,
	method: 'GET',
	path: '/'
};

for (var i = 2; i < process.argv.length; i++){
	var currentParam = process.argv[i];
	if (currentParam == 'verbose') yell = true;
}

var testCases = [];
var testCaseIndex = 0;

var currentTestCase = {strictMode: false, disallowSessions: false};
var state = 0;

do {
	testCases.push(clone(currentTestCase));
	state = currentTestCase.strictMode * 2 + currentTestCase.disallowSessions;
	state = (state + 1) % 4;
	currentTestCase.strictMode = (state & 0x02) == 2;
	currentTestCase.disallowSessions = (state & 0x01) == 1;
} while (state != 0);

function performTests(strictMode, disallowSessions, next, taskIndex, testTotal){
	if (typeof next != 'function') throw new TypeError('next must be a function');

	log('---------------NEW TEST CASE---------------');
	if (typeof testIndex == 'number' && typeof testTotal == 'number'){
		log('Test n. ' + (testIndex + 1) + ' out of '+ testTotal);
	}
	log('Strict mode: ' + strictMode);
	log('Disallow sessions: ' + disallowSessions);
	log('-------------------------------------------');

	function setupServer(N){
		testServer.clear();
		testServer.setServerPort(serverSettings.port);
		testServer.setup(strictMode, disallowSessions);

		log('Starting server');
		testServer.start(function(){
			log('Server has been started');
			N();
		});
	}

	function setupClient(N){
		testClient.setServerSettings(serverSettings);
		log('Starting client');
		testClient.start(function(){
			log('Generating identity key');
			testClient.setup(false, N);
		});
	}

	function testNormalRequests(N){
		var calls = [
			{f: testClient.unauthenticatedReq, a: [cbLoc], m: 'Testing an unauthenticated request'},
			{f: testClient.authenticatedReq, a: [cbLoc, false, strictMode, undefined, false], m: 'Authenticated request before registration. Expected failure'},
			{f: testClient.registrationReq, a: [cbLoc], m: 'User registration'},
			{f: testClient.authenticatedReq, a: [cbLoc, false, strictMode], m: 'Authenticated request'},
		];

		if (useExpress) calls.push({f: testClient.authenticatedReq, a: [cbLoc, true, strictMode], m: 'Authenticated request with FormData'});

		//Add key rotation task in all cases
		calls.push({f: testClient.keyRotationReq, a: [cbLoc, './newhpkaclient.key'], m: 'Testing key rotation request'});

		if (!disallowSessions){
			//Default TTL settings
			calls.push({f: setSessionTTL, a: [7 * 24 * 3600, cbLoc], m: 'Setting Session TTL to 7 days'});
			calls.push({f: testClient.sessionAgreementReq, a: [cbLoc, 0, undefined, undefined, 7 * 24 * 3600], m: 'Testing SessionId agreement'});
			calls.push({f: testClient.sessionAuthenticatedReq, a: [cbLoc, strictMode, undefined, true], m: 'Testing session-authenticated request'});
			calls.push({f: testClient.sessionRevocationReq, a: [cbLoc], m: 'Testing SessionId revocation'});
			calls.push({f: testClient.sessionAuthenticatedReq, a: [cbLoc, strictMode, undefined, false], m: 'Testing session-authenticated request, with now-revoked SessionId'});
			//No TTL
			calls.push({f: setSessionTTL, a: [0, cbLoc], m: 'Setting Session TTL to infinity'});
			calls.push({f: testClient.sessionAgreementReq, a: [cbLoc, 0, undefined, undefined, 0], m: 'Testing SessionId agreement, with no TTL'});
			calls.push({f: testClient.sessionAuthenticatedReq, a: [cbLoc, strictMode, undefined, true], m: 'Testing session-authenticated request, with a TTL-less SessionId'});
			calls.push({f: testClient.sessionRevocationReq, a: [cbLoc], m: 'Testing SessionId revocation'});
			calls.push({f: testClient.sessionAuthenticatedReq, a: [cbLoc, strictMode, undefined, false], m: 'Testing session-authenticated request, with now-revoked SessionId'});
			//TTL = 1 day
			calls.push({f: setSessionTTL, a: [24 * 3600, cbLoc], m: 'Setting Session TTL to one day'});
			calls.push({f: testClient.sessionAgreementReq, a: [cbLoc, 1200, undefined, undefined, now() + 1200], m: 'Testing SessionId agreement, with user-imposed TTL'});
			calls.push({f: testClient.sessionAuthenticatedReq, a: [cbLoc, strictMode, undefined, true], m: 'Testing session-authenticated request, with user-imposed TTL'});
			calls.push({f: testClient.sessionRevocationReq, a: [cbLoc], m: 'Testing SessionId revocation'});
			calls.push({f: testClient.sessionAuthenticatedReq, a: [cbLoc, strictMode, undefined, false], m: 'Testing session-authenticated request, with now-revoked SessionId'});
		}

		chainAsyncFunctions(calls, N);
	}

	function testSpoofedRequests(N){
		var calls = [
			{f: testClient.spoofedSignatureReq, a: [cbLoc, strictMode], m: 'Sending request with spoofed signature'},
			{f: testClient.spoofedHostReq, a: [cbLoc, strictMode], m: 'Sending request with wrong hostname and path'},
			{f: testClient.spoofedUsernameReq, a: ['test2', cbLoc, strictMode], m: 'Sending request with spoofed username'}
		];

		if (!disallowSessions) calls.push({f: testClient.spoofedSessionReq, a: ['test2', cbLoc, strictMode], m: 'Sending sessionId-backed request with spoofed username'});

		chainAsyncFunctions(calls, N);
	}

	function testMalformedRequests(N){
		var calls = [
			{f: testClient.malformedReq, a: [cbLoc, strictMode], m: 'Sending malformed authenticated request'},
			{f: testClient.malformedReqNonBase64, a: [cbLoc, strictMode], m: 'Sending fuzzing-like malformed authenticated request'}
		];

		if (!disallowSessions){
			calls.push({f: testClient.malformedSessionReq, a: [cbLoc, strictMode], m: 'Sending malformed sessionId-backed request'});
			calls.push({f: testClient.malformedSessionReqNonBase64, a: [cbLoc, strictMode], m: 'Sending fuzzing-like malformed sessionId-backed request'});
		}

		chainAsyncFunctions(calls, N);
	}

	function cleanup(N){

		var calls = [
			{f: testClient.deletionReq, a: [cbLoc], m: 'Deleting user account'},
			{f: testClient.authenticatedReq, a: [cbLoc, false, strictMode, undefined, false], m: 'Sending an authenticated request, with a deleted account. Expected failure'},
			{f: testServer.stop, a: [cbLoc], m: 'Stopping server'}
		];

		chainAsyncFunctions(calls, N);
	}

	function setSessionTTL(t, cb){
		testServer.setMaxSessionLife(t);
		cb();
	}

	var testGroups = [
		{f: setupServer, a: [cbLoc]},
		{f: setupClient, a: [cbLoc]},
		{f: testNormalRequests, a: [cbLoc]},
		//{f: testSpoofedRequests, a: [cbLoc]},
		//{f: testMalformedRequests, a: [cbLoc]},
		{f: cleanup, a: [cbLoc]}
	];

	chainAsyncFunctions(testGroups, function(){
		log('---------------END TEST CASE---------------');
		log('');
		next();
	});
}

function doTestCase(){
	var nextTestCase = testCases[testCaseIndex];

	performTests(nextTestCase.strictMode, nextTestCase.disallowSessions, function(){
		testCaseIndex++;
		if (testCaseIndex == testCases.length){ //All test cases have been executed
			log('HPKA.js testing completed with success');
			process.exit(0);
		} else doTestCase(); //Go to next test case
	}, testCaseIndex, testCases.length);
}

doTestCase();

function chainAsyncFunctions(functionsList, callback){
	var fIndex = 0;

	function doOne(){
		var theFunction = functionsList[fIndex].f;
		var theArguments = functionsList[fIndex].a.slice();
		insertCallbackInArguments(theArguments, next, true);

		if (functionsList[fIndex].m) log(functionsList[fIndex].m);

		theFunction.apply(this, theArguments);
	}

	function next(){
		fIndex++;
		if (fIndex == functionsList.length) callback();
		else { //Trying to limit the callstack size
			if (fIndex % 100 == 0) setTimeout(doOne, 0);
			else doOne();
		}
	}

	doOne();

}

function insertCallbackInArguments(ar, cb, assertFound){
	for (var i = 0; i < ar.length; i++){
		if (ar[i] == cbLoc){
			ar[i] = cb;
			return;
		}
	}
	if (assertFound) throw new Error('#cbhere# cannot be found in array: ' + JSON.stringify(ar));
}

function log(m){
	if (yell) console.log(m);
}

function now(){
	return Math.floor(Date.now() / 1000);
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
