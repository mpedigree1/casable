url = require 'url'
xmls2js = require 'xml2js'
http = require 'http'

class Cas2ValidationReader
	@validationUrl = '/serviceValidate'

	constructor: () ->

	read: (body, callback) ->
		xmls2js.parseString body, (error, result) ->
			if 'cas:authenticationFailure' of result['cas:serviceResponse']
				callback null, "Invalid Ticket or Service"
			else if 'cas:authenticationSuccess' of result['cas:serviceResponse']
				callback id: result['cas:serviceResponse']['cas:authenticationSuccess'][0]['cas:user'][0];

class Cas1ValidationReader
	@validationUrl = '/validate'

	constructor: () ->

	read: (body, callback) ->
		lines = body.split '\n'

		if lines.length >= 1
			if lines[0] == 'no'
				callback null, "Invalid Ticket or Service"

		else if lines[0] == 'yes' and lines.length >= 2
			callback id: lines[1]

class Casable
	constructor: (@ssoBaseURL, @config = {}) ->
		console.log "Starting Casable with CAS Server : " + @ssoBaseURL

		@parsedBaseUrl = url.parse @ssoBaseURL

		@logoutDestination = @config.logoutPath || '/';

		@loginURL = @ssoBaseURL + '/login'
		@logoutURL = @ssoBaseURL + '/logout'

	buildServiceUrl: (req) =>
		return url.format
			host: req.headers.host
			port: req.header.port
			protocol: 'http'
			pathname: req.url

	buildLogoutUrl: (req) ->
		return url.format
			host: req.headers.host
			protocol: 'http'
			port: req.headers.port
			pathname: @logoutDestination

	login: (res, req) =>
		redirectURL = url.parse @loginURL, true
		redirectURL.query.service = @buildServiceUrl req
		res.redirect url.format redirectURL

	logout: (req, res) =>
		if req.session? and req.session.authenticatedUser?
			req.session.authenticatedUser = null

		redirectURL = url.parse @logoutURL, true
		redirectURL.query.url = @buildLogoutUrl req
		res.redirect url.format redirectURL

	authenticate: (req, res, next) =>

		if req.route.path == '/logout'
			@logout req, res
			next()
			return

		if req.session? and req.session.authenticatedUser?
			req.authenticatedUser = req.session.authenticatedUser
			next()
			return

		ticket = req.param 'ticket'
		if ticket?
			@validate req, ticket, (user, error) ->
				if req.session?
					req.session.authenticatedUser = user
				req.authenticatedUser = user
				next()
				return
		else
			@login res, req

	validate: (req, ticket, callback) =>

		validateUrl = url.format
			pathname: "#{@parsedBaseUrl.path}#{Cas2ValidationReader.validationUrl}"
			query:
				ticket: ticket,
				service: @buildServiceUrl req

		delete parsedUrl.query.ticket if @parsedBaseUrl.query?

		req = http.get
			host: @parsedBaseUrl.hostname
			port: @parsedBaseUrl.port
			path: validateUrl, (res) ->
				res.setEncoding 'utf8'
				body = ''

				res.on 'data', (chunk) ->
					body += chunk

				res.on 'end', () ->
					new Cas2ValidationReader().read body, callback

		req.on 'error', (error) ->
			callback null, error

exports.authentication = (ssoBaseURL, config = {})->
	return new Casable(ssoBaseURL, config).authenticate