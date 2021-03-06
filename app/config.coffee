passport = require 'passport'
CitrixStrategy = require('passport-citrix-auth-service').Strategy
{DeviceAuthenticator} = require 'meshblu-authenticator-core'
debug = require('debug')('meshblu-citrix-authenticator:config')

citrixOauthConfig =
  clientID: process.env.CAS_CLIENT_ID
  clientSecret: process.env.CAS_CLIENT_SECRET
  callbackURL: process.env.CAS_CALLBACK_URL
  passReqToCallback: false

class CitrixConfig
  constructor: ({@meshbluHttp, @meshbluJSON}) ->

  register: =>
    passport.use new CitrixStrategy citrixOauthConfig, @onAuthentication

  onAuthentication: (accessToken, refreshToken, profile, done) =>
    profileId = profile.id
    fakeSecret = 'citrix-authenticator'
    authenticatorUuid = @meshbluJSON.uuid
    authenticatorName = @meshbluJSON.name
    deviceModel = new DeviceAuthenticator {authenticatorUuid, authenticatorName, @meshbluHttp}
    query = {}
    query[authenticatorUuid + '.id'] = profileId
    device =
      name: "#{profile.name.givenName} #{profile.name.familyName}"
      type: 'octoblu:user'

    getDeviceToken = (uuid) =>
      @meshbluHttp.generateAndStoreToken uuid, (error, device) =>
        device.id = profileId
        done null, device

    deviceCreateCallback = (error, createdDevice) =>
      return done error if error?
      getDeviceToken createdDevice?.uuid

    deviceFindCallback = (error, foundDevice) =>
      return getDeviceToken foundDevice.uuid if foundDevice?
      deviceModel.create
        query: query
        data: device
        user_id: profileId
        secret: fakeSecret
      , deviceCreateCallback

    deviceModel.findVerified query: query, password: fakeSecret, deviceFindCallback

module.exports = CitrixConfig
