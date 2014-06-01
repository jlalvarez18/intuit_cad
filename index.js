var moment = require('moment');
var UUID = require('node-uuid');
var fs = require('fs');
var querystring = require('querystring');

var crypto = require('crypto');
var https = require('https');
var OAuth = require('oauth-1.0a');

var baseUrl = 'financialdatafeed.platform.intuit.com'

function CAD() {}

function _initialize(oauthConsumerKey, oauthSecretKey, providerId) {
	this._consumerKey = oauthConsumerKey;
	this._consumerSecretKey = oauthSecretKey;
	this._providerId = providerId;
	
	this._oauthToken = '';
	this._oauthTokenSecret = '';
	this._oauthExpirationDate = moment().subtract('day', 1);
}

function _getKeys() {
	return 'Consumer: ' + cad._consumerKey + ' Secret: ' + cad._consumerSecretKey;
}

function _getOAuthTokens(customerId, callback) {
	var now = moment();
	
	var expirationDate = cad._oauthExpirationDate || moment().subtract('day', 1);
	
	if (_areOAuthKeysExpired()) {
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
					cad._oauthToken = result['oauth_token'];
					cad._oauthTokenSecret = result['oauth_token_secret'];
					cad._oauthExpirationDate = moment().add('hours', 1);
				
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
	} else {
		var result = {
			oauth_token: cad._oauthToken,
			oauth_token_secret: cad._oauthTokenSecret
		}
		
		callback(null, result);
	}
}

function _getAllInstitutions(callback) {
	var path = '/v1/institutions';
	
	var timeout = 5*60*1000;
	
	_getRequest(path, callback, timeout);
}

// Get details for the Institution ID
// callback signature function(error, response) {}

function _getInstitutionDetails(institutionId, callback) {
	var path = '/v1/institutions/' + institutionId;
	
	_getRequest(path, callback);
}

var cad = module.exports = exports = new CAD();

CAD.prototype.initialize = _initialize;
CAD.prototype.getKeys = _getKeys;
CAD.prototype.getOAuthTokens = _getOAuthTokens;
CAD.prototype.getAllInstitutions = _getAllInstitutions;
CAD.prototype.getInstitutionDetails = _getInstitutionDetails;

////// Private Functions //////

// Get details for the Institution ID
// callback signature function(error, response, body) {}

function _getRequest(path, callback, timeout) {
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
	    public: cad._oauthToken,
	    secret: cad._oauthTokenSecret
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

function _areOAuthKeysExpired() {
	var now = moment();
	
	var expirationDate = cad._oauthExpirationDate || moment().subtract('day', 1);
	
	if (now.isAfter(expirationDate)) {
		return true;
	}
	
	return false;
}

function _prepSAMLAssertion(customerId, providerId) {
	var dateFormat = "YYYY-MM-DD'T'HH:mm:ss.SSS'Z'";
	
	var keysPath = './keys';
	var xmlPath = './keys';
	
	var now = moment.utc();
	var nowString = now.toISOString()//.format(dateFormat);
	
	var now15Min = now.add('m', 15);
	var now15MinString = now15Min.toISOString()//.format(dateFormat);
	
	var refId = UUID.v1();
	var x509 = fs.readFileSync(keysPath + '/app.crt', 'utf8');
	var privKey = fs.readFileSync(keysPath + '/app.key', 'utf8');
	
	// Create ASSERTION	
	var assertion = fs.readFileSync('./keys/assertion.xml', 'utf8');
	
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
	var signedInfo = fs.readFileSync(xmlPath + '/signed_info.xml', 'utf8');
	
	signedInfo = replaceAll('REFERENCE_ID', refId, signedInfo);
	signedInfo = replaceAll('DIGEST', assertionDigest, signedInfo);
	
	var SIGN = crypto.createSign('SHA1');
	SIGN.update(signedInfo);
	
	var signatureValue = SIGN.sign(privKey, 'base64');
	
	// Create SIGNATURE
	var signature = fs.readFileSync(xmlPath + '/signature.xml', 'utf8');
	
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