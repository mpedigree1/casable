var url = require('url'),
	http = require('http'),
	util = require('util');

var xmls2js = require('xml2js');

var parsedUrl;

var buildServiceUrl = function(req){
	return url.format({
		host: req.headers.host,
		protocol: 'http',
		port: req.headers.port,
		pathname: req.url
	});
}

var buildLogoutUrl = function(req, logoutDestination){
	return url.format({
		host: req.headers.host,
		protocol: 'http',
		port: req.headers.port,
		pathname: logoutDestination
	});
}

var responseReaderVersion1 = function(body, whenDone){
	var lines = body.split('\n');

	if (lines.length >= 1){
		if (lines[0] == 'no'){
			whenDone(null, "Invalid Ticket or Service");
		}
		else if ((lines[0] == 'yes') &&
			(lines.length >= 2)) {

			whenDone({id:lines[1]});
		}
	}
}

var responseReaderVersion2 = function(body, whenDone){
	xmls2js.parseString(body, function(error, result){

		if ('cas:authenticationFailure' in result['cas:serviceResponse']){
			whenDone(null, "Invalid Ticket or Service");
		}
		else if ('cas:authenticationSuccess' in result['cas:serviceResponse']){
			whenDone({id: result['cas:serviceResponse']['cas:authenticationSuccess'][0]['cas:user'][0]});
		}
	});
}

var validate = function(req, ticket, whenDone){

	var validateUrl = url.format({
		pathname: parsedUrl.path + '/serviceValidate',
		query:{
			ticket:ticket,
			service: buildServiceUrl(req)
		}
	});

	if (parsedUrl.query) delete parsedUrl.query.ticket;

	var req = http.get({
		host: parsedUrl.hostname,
		port: parsedUrl.port,
		path: validateUrl
	}, function(res){
		res.setEncoding('utf8');
		var body = '';

		res.on('data', function(chunk){
			body += chunk;
		});

		res.on('end', function(){
			responseReaderVersion2(body, whenDone);
		});
	});

	req.on('error', function(error){
		whenDone(null, error);
	})
}

var killSession = function(req){
	req.session = null;
}

var goToLogin = function(res, req, loginURL){
	var redirectURL = url.parse(loginURL, true);
	redirectURL.query.service = buildServiceUrl(req);
	res.redirect(url.format(redirectURL));
}

exports.authenticationMiddleware = function(ssoBaseURL, options){

	if (!options) options = {};

	parsedUrl = url.parse(ssoBaseURL);

	var loginURL = ssoBaseURL + '/login';
	var logoutURL = ssoBaseURL + '/logout';

	var logoutDestination = options.logoutPath || '/';

	return function(req, res, next){

		if (req.route.path == '/logout'){

			killSession(req);

			var redirectURL = url.parse(logoutURL, true);
			redirectURL.query.url = buildLogoutUrl(req, logoutDestination);
			res.redirect(url.format(redirectURL));
			next();
			return;
		}
		if (req.session){
			if (req.session.authenticatedUser){
				req.authenticatedUser = req.session.authenticatedUser;
				next();
				return;
			}
		}
		var ticket = req.param('ticket');

		if (ticket){
			validate(req, ticket, function(user, error){
				if (req.session){
					req.session.authenticatedUser = user;
				}
				req.authenticatedUser = user;
				next();
				return;
			});
		}
		else{
			goToLogin(res, req, loginURL);
		}
	}
}