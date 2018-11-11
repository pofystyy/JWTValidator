require_relative 'auth'

class Client

  include JWToken

  attr_reader :token

  def initialize name = ''
    create_rsa_keys
    @name = name
    @token = create_token payload
  end

  private

  def exp
    Time.now.to_i + 5 * 60
  end

  def payload
    { name: @name, exp: exp }
  end

end

