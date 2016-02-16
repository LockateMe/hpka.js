var ph = require('phantom');
var phOptions = {};

var phantom;
var testPage;

var serverSettings;

exports.setServerSettings = function(_serverSettings){
	if (typeof _serverSettings != 'object') throw new TypeError('_serverSettings must be an object');

	serverSettings = _serverSettings;
};

exports.start = function(cb){
	if (cb && typeof cb != 'function') throw new TypeError('when defined, cb must be a function');

	if (phantom){
		if (cb) cb();
		return;
	}

	ph.create(phOptions).then(function(pInstance){
		phantom = pInstance;

		phantom.createPage().then(function(_p){
			testPage = _p;
			phantom.open('http://' + serverSettings.hostname + ':' + serverSettings.port + '/unit.html').then(function(status){
				console.log('Page loading status: ' + status);

				if (cb) cb();
			});
		});
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
