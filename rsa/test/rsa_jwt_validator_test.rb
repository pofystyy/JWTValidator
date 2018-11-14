require 'minitest/autorun'
require 'jwt'
require_relative '../lib/jwt_validator'

class JwtValidatiorTest < Minitest::Test
  def setup
    @rsa_private = OpenSSL::PKey::RSA.generate 2048
    @rsa_public = @rsa_private.public_key
    @rsa_alghorythm = 'RS256'.freeze
    @valid_payload = {
      'user_id' => 1,
      'exp' => Time.now.to_i + 4 * 3600
    }.freeze
    @valid_token = JWT.encode(@valid_payload, @rsa_private, @rsa_alghorythm)
  end

  def test_raises_exception_with_ivalid_algorithm
    assert_raises JwtValidatior::Exceptions::InvalidAlgorithm do
      JwtValidatior::Validator.call(@valid_token, algorithm: :invalid, algorithm_params: {})
    end
  end

  def test_valid_token_with_rsa_raise_no_error
    result = JwtValidatior::Validator.call(@valid_token,
                                           algorithm: :rsa,
                                           algorithm_params: { rsa_public: @rsa_public, alg: @rsa_alghorythm })
    assert_equal @valid_payload, result
  end

  def test_expired_token_raises_exception
    payload = {
      'user_id' => 1,
      'exp' => Time.now.to_i - 4 * 3600
    }
    token = JWT.encode(payload, @rsa_private, @rsa_alghorythm)
    assert_raises JwtValidatior::Exceptions::ExpiredToken do
      JwtValidatior::Validator.call(token,
                                    algorithm: :rsa,
                                    algorithm_params: { rsa_public: @rsa_public, alg: @rsa_alghorythm })
    end
  end

  def test_invalid_hash_alg_raises_exception
    assert_raises JwtValidatior::Exceptions::InvalidAlgorithm do

      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :invalid,
                                    algorithm_params: { rsa_public: @rsa_public, alg: @rsa_alghorythm })
    end
  end

  def test_invalid_rsa_public_key_raises_exception
    invalid_key = OpenSSL::PKey::RSA.generate 2048
    assert_raises JwtValidatior::Exceptions::IvalidToken do
      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :rsa,
                                    algorithm_params: { rsa_public: invalid_key, alg: @rsa_alghorythm })
    end
  end

  def test_missing_alg_key_raises_exception
    assert_raises JwtValidatior::Algorithms::Rsa::Exceptions::MissingRequiredKey do
      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :rsa,
                                    algorithm_params: { rsa_public: @rsa_public })
    end
  end

  def test_invalid_alg_key_raises_exception
    assert_raises JwtValidatior::Algorithms::Rsa::Exceptions::InvalidRsaAlgorithm do
      JwtValidatior::Validator.call(@valid_token,
                                    algorithm: :rsa,
                                    algorithm_params: { rsa_public: @rsa_public, alg: :invalid })
    end
  end
end
