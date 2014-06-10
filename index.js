var moment = require('moment');
var UUID = require('node-uuid');
var fs = require('fs');
var querystring = require('querystring');

var crypto = require('crypto');
var https = require('https');
var OAuth = require('oauth-1.0a');
var path = require('path');

var baseUrl = 'financialdatafeed.platform.intuit.com'

function CAD() {}

function _initialize(values) {
	var oauthConsumerKey = values['consumer_key'];
	var oauthSecretKey = values['secret_key'];
	var providerId = values['provider_id'];
	
	var certPath = values['certificate_path'];
	var privPath = values['private_key_path'];
	
	this._consumerKey = oauthConsumerKey;
	this._consumerSecretKey = oauthSecretKey;
	this._providerId = providerId;
	this._certificatePath = certPath;
	this._privateKeyPath = privPath;
}

function _getConsumerKeys() {
	return 'Consumer: ' + cad._consumerKey + ' Secret: ' + cad._consumerSecretKey;
}

function _getOAuthTokens(customerId, callback) {
	customerId = customerId || 'default';
	
	var assertion = _prepSAMLAssertion(customerId, cad._providerId);

	var query = { saml_assertion: assertion };
	var body = querystring.stringify(query);

	var options = {
		host: 'oauth.intuit.com',
		path: '/oauth/v1/get_access_token_by_saml',
		method: 'POST',
		headers: { 
			'Authorization': 'OAuth oauth_consumer_key=' + '"' + cad._consumerKey + '"',
			'Content-Type': 'application/x-www-form-urlencoded',
			'Content-Length': body.length
		}
	};

	var req = https.request(options, function(res) {
		// console.log('STATUS: ' + res.statusCode);
		// console.log('HEADERS: ' + JSON.stringify(res.headers));

		var str = '';

		res.on('data', function(chunk) {
			str += chunk;
		});

		res.on('end', function() {
			var cleanString = querystring.unescape(str);
	
			var result = querystring.parse(str);
	
			var oauth_problem = result['oauth_problem'];
	
			if (oauth_problem != null) {
				callback(oauth_problem, null);
			} else {
				result['oauth_exp_date'] = moment().add('hours', 1);
				
				callback(null, result);
			}
		});
	});

	req.on('error', function(e) {
	  console.log('problem with request: ' + e.message);

	  callback(e, null);
	});

	req.write(body);

	req.end();
}

function _getAllInstitutions(callback) {
	cad.getOAuthTokens(null, function(err, value) {
		if (err) {
			callback(err, null);
		} else {
			var oauthToken = value['oauth_token'];
			var oauthTokenSecret = value['oauth_token_secret'];
			
			var path = '/v1/institutions';
	
			var timeout = 5*60*1000;
			
			_getRequest(path, oauthToken, oauthTokenSecret, callback, timeout);
		}
	});
}

function _getInstitutionDetails(institutionId, callback) {
	cad.getOAuthTokens(null, function(err, value) {
		var oauthToken = value['oauth_token'];
		var oauthTokenSecret = value['oauth_token_secret'];
		
		var path = '/v1/institutions/' + institutionId;
	
		_getRequest(path, oauthToken, oauthTokenSecret, callback);
	});
}

var cad = module.exports = exports = new CAD();

CAD.prototype.initialize = _initialize;
CAD.prototype.getConsumerKeys = _getConsumerKeys;
CAD.prototype.getOAuthTokens = _getOAuthTokens;
CAD.prototype.getAllInstitutions = _getAllInstitutions;
CAD.prototype.getInstitutionDetails = _getInstitutionDetails;

////// Private Functions //////

function _getRequest(path, oauth_token, oauth_secret, callback, timeout) {
	if (!path || !oauth_token || !oauth_secret) {
		callback('_getRequest requires path, oauth_token and oauth_secret', null);
	} else {
		var oauth = OAuth({
			consumer: {
				public: cad._consumerKey,
				secret: cad._consumerSecretKey
			}
		});
	
		var url = 'https://' + baseUrl + path;
	
		var requestData = {
		    url: url,
		    method: 'GET'
		};
	
		var token = {
		    public: oauth_token,
		    secret: oauth_secret
		};
	
		var authHeader = oauth.toHeader(oauth.authorize(requestData, token));
	
		var headers = {
			Accept: 'application/json',
			Authorization: authHeader['Authorization']
		};
	
		var requestOptions = {
			host: baseUrl,
			path: path,
			method: requestData.method,
			headers: headers
		};
	
		timeout = timeout || 0;
	
		console.log('Timeout:' + timeout);
	
		var req = https.request(requestOptions, function(res) {
			console.log('RESPONSE STATUS: ' + res.statusCode);
			console.log('RESPONSE HEADERS: ' + JSON.stringify(res.headers));
		
			var str = '';
	
			res.on('data', function(chunk) {
				str += chunk;
			});
	
			res.on('end', function() {
				var result = JSON.parse(str);
		
				callback(null, result);
			});
		});
	
		// req.setTimeout(timeout, function(argument) {
		// 	var error = JSON.parse({error: 'Request timed out'});
		// 	
		// 	callback(error, null);
		// });
		
		req.on('error', function(e) {
		  console.log('problem with request: ' + e.message);
	  
		  var error = JSON.parse({error: e});
		  
		  callback(error, null);
		});
		
		req.end();
	}
}

function _areOAuthKeysExpired(date) {
	var now = moment();
	
	var expirationDate = date || moment().subtract('day', 1);
	
	if (now.isAfter(expirationDate)) {
		return true;
	}
	
	return false;
}

function _prepSAMLAssertion(customerId, providerId) {	
	var xmlPath = path.join(__dirname, 'saml_xml');
	
	var now = moment.utc();
	var nowString = now.toISOString();
	
	var now15Min = now.add('m', 15);
	var now15MinString = now15Min.toISOString();
	
	var refId = UUID.v1();
	var x509 = fs.readFileSync(cad._certificatePath, 'utf8');
	var privKey = fs.readFileSync(cad._privateKeyPath, 'utf8');
	
	// Create ASSERTION	
	var assertion = fs.readFileSync(path.join(xmlPath, 'assertion.xml'), 'utf8');
	
	function replaceAll(find, replace, str) {
		var find = find.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
		
		return str.replace(new RegExp(find, 'g'), replace);
	}
	
	assertion = replaceAll('CURRENT_DATE', nowString, assertion);
	assertion = replaceAll('CONDITION_BEFORE', nowString, assertion);
	assertion = replaceAll('CONDITION_AFTER', now15MinString, assertion); 
	assertion = replaceAll('REFERENCE_ID', refId, assertion);
	assertion = replaceAll('PROVIDER_ID', providerId, assertion);
	assertion = replaceAll('CUSTOMER_ID', customerId, assertion);
	
	var SHAHash = crypto.createHash('sha1');
	SHAHash.update(assertion);
	var assertionDigest = SHAHash.digest('base64');
	
	// Create SIGNED INFO
	var signedInfo = fs.readFileSync(path.join(xmlPath, 'signed_info.xml'), 'utf8');
	
	signedInfo = replaceAll('REFERENCE_ID', refId, signedInfo);
	signedInfo = replaceAll('DIGEST', assertionDigest, signedInfo);
	
	var SIGN = crypto.createSign('SHA1');
	SIGN.update(signedInfo);
	
	var signatureValue = SIGN.sign(privKey, 'base64');
	
	// Create SIGNATURE
	var signature = fs.readFileSync(path.join(xmlPath, 'signature.xml'), 'utf8');
	
	signature = replaceAll('REFERENCE_ID', refId, signature);
	signature = replaceAll('DIGEST', assertionDigest, signature);
	signature = replaceAll('SIGNATURE_VALUE', signatureValue, signature);
		
	// Insert Assertion
	var issuerString = '</saml2:Issuer>';
	var insertionIndex = assertion.indexOf(issuerString) + issuerString.length;
	
	assertion = assertion.insert(insertionIndex, signature);
	
	return assertion;
}

String.prototype.insert = function (index, string) {
  if (index > 0)
    return this.substring(0, index) + string + this.substring(index, this.length);
  else
    return string + this;
};