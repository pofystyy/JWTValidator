require_relative 'rsa_keys'

module JWToken

  require 'jwt'

  def self.included klass
    klass.class_eval do
      include OpenSSL
    end
  end

  ALGO = 'RS256'

  def create_token payload
    JWT.encode payload, rsa_private, ALGO
  end

  def decoded token
    begin
      JWT.decode token, rsa_public, true, { :algorithm => ALGO }
    rescue JWT::ExpiredSignature
    end
  end

end