url = require 'url'
xmls2js = require 'xml2js'
http = require 'http'

class Cas2ValidationReader
	
	validationUrl: () ->
		return '/serviceValidate'

	constructor: () ->

	read: (body, callback) ->
		xmls2js.parseString body, (error, result) ->
			if 'cas:authenticationFailure' of result['cas:serviceResponse']
				callback null, "Invalid Ticket or Service"
			else if 'cas:authenticationSuccess' of result['cas:serviceResponse']
				auth = result['cas:serviceResponse']['cas:authenticationSuccess'][0]

				session = 
					id: auth['cas:user'][0]
					name: auth['cas:name'][0]
					surname: auth['cas:surname'][0]
					email: auth['cas:email'][0]
					salt: auth['cas:salt'][0]
					passwordHash: auth['cas:passwordHash'][0]

				callback session


class Cas1ValidationReader
	validationUrl: () ->
		return '/validate'

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
		@parsedBaseUrl = url.parse @ssoBaseURL

		@logoutDestination = @config.logoutPath || '/'
		@casVersion = @config.casVersion || '2.0'

		@loginURL = @ssoBaseURL + '/login'
		@logoutURL = @ssoBaseURL + '/logout'

		@cookieName = @config.cookieName

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
			pathname: @logoutURL

	login: (res, req) =>
		redirectURL = url.parse @loginURL, true
		redirectURL.query.service = @buildServiceUrl req
		res.redirect url.format redirectURL

	logout: (req, res) =>
		if req.session?
			req.session.authenticatedUser = null

		req.authenticatedUser = null

		redirectURL = url.parse @logoutURL

		res.redirect url.format redirectURL

	authenticate: (req, res, next) =>

		if req.route.path == '/logout'
			@logout req, res
			next()
			return

		if (@cookieName)
			if not req.cookies[@cookieName]
				if req.session?
					req.session.authenticatedUser = null
				req.authenticatedUser = null

				@login res, req
				return

		if req.session? and req.session.authenticatedUser?
			req.authenticatedUser = req.session.authenticatedUser
			next()
			return

		ticket = req.param 'ticket'
		if ticket?
			@validate req, ticket, (user, error) =>
				if req.session? and user?
					req.session.authenticatedUser = user
				req.authenticatedUser = user
				next()
				return
		else
			@login res, req

	validate: (req, ticket, callback) =>

		reader = if @casVersion == "2.0" then new Cas2ValidationReader() else new Cas1ValidationReader()

		validateUrl = url.format
			pathname: "#{@parsedBaseUrl.path}#{reader.validationUrl()}"
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
					reader.read body, callback

		req.on 'error', (error) ->
			callback null, error

exports.authentication = (ssoBaseURL, config = {})->
	return new Casable(ssoBaseURL, config).authenticate