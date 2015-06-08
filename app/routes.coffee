passport = require 'passport'
url      = require 'url'
debug    = require('debug')('meshblu-citrix-authenticator:routes')

class Router
  constructor: (@app) ->

  register: =>
    @app.get  '/', (request, response) => response.status(200).send status: 'online'

    @app.get '/login', @addTokenParam, @storeCallbackUrl, passport.authenticate 'oauth2'

    @app.get '/oauthcallback', passport.authenticate('oauth2', { failureRedirect: '/login' }), @afterPassportLogin

  afterPassportLogin: (request, response) =>
    debug 'AfterPassportLogin', request, response
    {callbackUrl} = request.cookies
    response.cookie 'callbackUrl', null, maxAge: -1
    return response.status(401).send(new Error 'Invalid User') unless request.user
    return response.status(201).send(request.user) unless callbackUrl?
    uriParams = url.parse callbackUrl, true
    delete uriParams.search
    uriParams.query ?= {}
    uriParams.query.uuid = request.user.uuid
    uriParams.query.token = request.user.token
    return response.redirect(url.format uriParams)

  defaultRoute: (request, response) =>
    response.render 'index'

  addTokenParam: (request, response, next) =>
    if !request.query.response_type?
      request.query['response_type'] = 'token'
    next()

  storeCallbackUrl: (request, response, next) =>
    if request.query.callback?
      response.cookie 'callbackUrl', request.query.callback, maxAge: 60 * 60 * 1000
    else
      response.cookie 'callbackUrl', null, maxAge: -1
    next()

module.exports = Router
