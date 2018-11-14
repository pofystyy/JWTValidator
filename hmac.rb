require 'openssl'
require 'jwt'

hmac_secret = 'my$ecretK3y'
iat = Time.now.to_i
payload = {:data => 'test', iat: iat}

token = JWT.encode payload, hmac_secret, 'HS256'

# eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoidGVzdCJ9.pNIWIL34Jo13LViZAJACzK6Yf0qnvT_BuwOxiMCPE-Y
puts token

decoded_token = JWT.decode token, hmac_secret, true, { algorithm: 'HS256' }

# Array
# [
#   {"data"=>"test"}, # payload
#   {"alg"=>"HS256"} # header
# ]
puts decoded_token

p Time.now#.to_i# + 4 * 3600