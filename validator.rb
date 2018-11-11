require_relative 'auth'

class Validator

  include JWToken

  def initialize user_token
    @user_token = user_token
  end

  def valid?
    @user_token == checking_out_token
  end

  private

  def payload
    decoded(@user_token)[0]
  end

  def checking_out_token
    data payload
  end

  def data hsh
    create_token hsh
  end

end