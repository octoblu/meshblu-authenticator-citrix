describe 'does it crash the right way?', ->
  it 'should crash, but only the way we want it to', ->
    try
      @sut = require '../server'
    catch error
      expect(error.message).to.equal 'OAuth2Strategy requires a clientID option'      
