require_relative 'client'
require_relative 'validator'

user = Client.new 'Mary'

p Validator.new(user.token).valid?
