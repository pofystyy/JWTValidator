require_relative 'client'
require_relative 'validator'

user = Client.new 'Mary'

token = Validator.new user.token
p token.valid?

