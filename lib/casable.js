// Generated by CoffeeScript 1.7.1
(function() {
  var Cas1ValidationReader, Cas2ValidationReader, Casable, http, url, xmls2js,
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  url = require('url');

  xmls2js = require('xml2js');

  http = require('http');

  Cas2ValidationReader = (function() {
    Cas2ValidationReader.validationUrl = '/serviceValidate';

    function Cas2ValidationReader() {}

    Cas2ValidationReader.prototype.read = function(body, callback) {
      return xmls2js.parseString(body, function(error, result) {
        if ('cas:authenticationFailure' in result['cas:serviceResponse']) {
          return callback(null, "Invalid Ticket or Service");
        } else if ('cas:authenticationSuccess' in result['cas:serviceResponse']) {
          return callback({
            id: result['cas:serviceResponse']['cas:authenticationSuccess'][0]['cas:user'][0]
          });
        }
      });
    };

    return Cas2ValidationReader;

  })();

  Cas1ValidationReader = (function() {
    Cas1ValidationReader.validationUrl = '/validate';

    function Cas1ValidationReader() {}

    Cas1ValidationReader.prototype.read = function(body, callback) {
      var lines;
      lines = body.split('\n');
      if (lines.length >= 1) {
        if (lines[0] === 'no') {
          return callback(null, "Invalid Ticket or Service");
        }
      } else if (lines[0] === 'yes' && lines.length >= 2) {
        return callback({
          id: lines[1]
        });
      }
    };

    return Cas1ValidationReader;

  })();

  Casable = (function() {
    function Casable(ssoBaseURL, config) {
      this.ssoBaseURL = ssoBaseURL;
      this.config = config != null ? config : {};
      this.validate = __bind(this.validate, this);
      this.authenticate = __bind(this.authenticate, this);
      this.logout = __bind(this.logout, this);
      this.login = __bind(this.login, this);
      this.buildServiceUrl = __bind(this.buildServiceUrl, this);
      console.log("Starting Casable with CAS Server : " + this.ssoBaseURL);
      this.parsedBaseUrl = url.parse(this.ssoBaseURL);
      this.logoutDestination = this.config.logoutPath || '/';
      this.loginURL = this.ssoBaseURL + '/login';
      this.logoutURL = this.ssoBaseURL + '/logout';
    }

    Casable.prototype.buildServiceUrl = function(req) {
      return url.format({
        host: req.headers.host,
        port: req.header.port,
        protocol: 'http',
        pathname: req.url
      });
    };

    Casable.prototype.buildLogoutUrl = function(req) {
      return url.format({
        host: req.headers.host,
        protocol: 'http',
        port: req.headers.port,
        pathname: this.logoutDestination
      });
    };

    Casable.prototype.login = function(res, req) {
      var redirectURL;
      redirectURL = url.parse(this.loginURL, true);
      redirectURL.query.service = this.buildServiceUrl(req);
      return res.redirect(url.format(redirectURL));
    };

    Casable.prototype.logout = function(req, res) {
      var redirectURL;
      if ((req.session != null) && (req.session.authenticatedUser != null)) {
        req.session.authenticatedUser = null;
      }
      redirectURL = url.parse(this.logoutURL, true);
      redirectURL.query.url = this.buildLogoutUrl(req);
      return res.redirect(url.format(redirectURL));
    };

    Casable.prototype.authenticate = function(req, res, next) {
      var ticket;
      if (req.route.path === '/logout') {
        this.logout(req, res);
        next();
        return;
      }
      if ((req.session != null) && (req.session.authenticatedUser != null)) {
        req.authenticatedUser = req.session.authenticatedUser;
        next();
        return;
      }
      ticket = req.param('ticket');
      if (ticket != null) {
        return this.validate(req, ticket, function(user, error) {
          if (req.session != null) {
            req.session.authenticatedUser = user;
          }
          req.authenticatedUser = user;
          next();
        });
      } else {
        return this.login(res, req);
      }
    };

    Casable.prototype.validate = function(req, ticket, callback) {
      var validateUrl;
      validateUrl = url.format({
        pathname: "" + this.parsedBaseUrl.path + Cas2ValidationReader.validationUrl,
        query: {
          ticket: ticket,
          service: this.buildServiceUrl(req)
        }
      });
      if (this.parsedBaseUrl.query != null) {
        delete parsedUrl.query.ticket;
      }
      req = http.get({
        host: this.parsedBaseUrl.hostname,
        port: this.parsedBaseUrl.port,
        path: validateUrl
      }, function(res) {
        var body;
        res.setEncoding('utf8');
        body = '';
        res.on('data', function(chunk) {
          return body += chunk;
        });
        return res.on('end', function() {
          return new Cas2ValidationReader().read(body, callback);
        });
      });
      return req.on('error', function(error) {
        return callback(null, error);
      });
    };

    return Casable;

  })();

  exports.authentication = function(ssoBaseURL, config) {
    if (config == null) {
      config = {};
    }
    return new Casable(ssoBaseURL, config).authenticate;
  };

}).call(this);