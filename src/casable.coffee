url = require 'url'
xmls2js = require 'xml2js'
http = require 'http'
https = require 'https'

class CasNoServiceValidationReader
	
	validationUrl: () ->
		return '/serviceAuthorisation'

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
					group: auth['cas:group'][0]

				callback session

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
					group: auth['cas:group'][0]

				callback session


class Cas1ValidationReader
	validationUrl: () ->
		return '/validate'

	constructor: () ->

	read: (body, callback) ->
		lines = body.split '\n'
		#Cas1ValidationReader (body.split).lengt==3 always
		if lines[0] == 'no'
				callback null, "Invalid Ticket or Service"

		else if lines[0] == 'yes' and lines.length >= 2
			callback id: lines[1]

class Casable
	constructor: (@ssoBaseURL, @config = {}) ->
		@parsedBaseUrl = url.parse @ssoBaseURL

		@logoutDestination = @config.logoutPath || '/'
		@casVersion = @config.casVersion || '2.0'
		#handleLogoutRequests from server ip
		@handleLogoutRequests=@config.handleLogoutRequests||['10.8.11.7']
		@loginURL = @ssoBaseURL + '/login'
		@logoutURL = @ssoBaseURL + '/logout'

		@cookieName = @config.cookieName

	buildServiceUrl: (req) =>
		return url.format
			host: req.headers.host
			protocol: req.protocol
			pathname: req.path

	buildLogoutUrl: (req) ->
		return url.format
			host: req.headers.host
			protocol: req.protocol
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

	authorise: (req, res, next) =>
		ticket = req.headers['x-ticket']

		if ticket?
			@validate req, ticket, (user, error) =>
				if user?
					next()
				else
					res.send 403
		else
			res.send 403

	authenticate: (req, res, next) =>
		#req.route.path is undefined
		if req.path == @logoutDestination
			@logout req, res
			#cannot modify header after send
			return

		#handleLogoutRequests post from  cas server
		if req.ip in @handleLogoutRequests and req.method=='POST'
			xmls2js.parseString req.body.logoutRequest, (error, result) =>
				req.sessionStore.destroy result['samlp:LogoutRequest']['samlp:SessionIndex'][0],@logout req, res
				return

		if @cookieName
			if not req.cookies[@cookieName]
				if req.session?
					req.session.authenticatedUser = null
				req.authenticatedUser = null

				@login res, req
				return

		# validate ticket
		ticket = req.query.ticket
		if not req.session.authenticatedUser? and not ticket?
			@login res, req
		else if ticket?
			@validate req,ticket,(user, error)=>
						if not user?
							@login res, req
						else
							user.ticket=ticket
							req.session.authenticatedUser = user
							req.authenticatedUser=user
							req.sessionStore.set ticket,req.session;
							next()
		else
			#Judge sessionStore has ticket
			req.sessionStore.get req.session.authenticatedUser.ticket,(error,is_login) =>
				if is_login?
					next()
				else
					req.session.authenticatedUser=null
					@login res, req

	validate: (req, ticket, callback) =>

		reader = switch
			when @casVersion == "2.0" then new Cas2ValidationReader()
			when @casVersion == "SERVICE" then new CasNoServiceValidationReader()
			else new Cas1ValidationReader()

		delete req.query.ticket

		validateUrl = url.format
			pathname: "#{reader.validationUrl()}"
			query:
				ticket: ticket,
				service: @buildServiceUrl req

		httpGet = (res) ->
			res.setEncoding 'utf8'
			body = ''

			res.on 'data', (chunk) ->
				body += chunk

			res.on 'end', () ->
				reader.read body, callback

		if @parsedBaseUrl.protocol == 'https:'
			validateRequest = https.get "#{@parsedBaseUrl.href}#{validateUrl}", httpGet
		else
			validateRequest = http.get "#{@parsedBaseUrl.href}#{validateUrl}", httpGet

		validateRequest.on 'error', (error) ->
			callback null, error

exports.authentication = (ssoBaseURL, config = {})->
	return new Casable(ssoBaseURL, config).authenticate

exports.authorisation = (ssoBaseURL, config = {}) ->
	return new Casable(ssoBaseURL, config).authorise
