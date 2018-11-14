require 'jwt'
require_relative '../base_service'

module JwtValidatior
  module Algorithms
  class Rsa < BaseService
    class Exceptions
      class BaseRsaException < JwtValidatior::Exceptions::BaseException; end
      class InvalidRsaAlgorithm < BaseRsaException; end
      class MissingRequiredKey < BaseRsaException; end
    end

    VALID_ALGORITHMS = %w[RS256].freeze
    VALID_KEYS = %i[rsa_public alg].freeze

    def initialize(payload, params)
      @payload = payload
      @params = params
    end

    def call
      raise Exceptions::MissingRequiredKey, "missing keys: #{@params.keys}" unless required_keys_present?
      raise Exceptions::InvalidRsaAlgorithm, "invalid alg: #{@params[:alg]}" unless valid_algorithm?
      decode
    end

    private

    def valid_algorithm?
      VALID_ALGORITHMS.include?(@params[:alg])
    end

    def required_keys_present?
      (VALID_KEYS - @params.keys).empty?
    end

    def decode
      JWT.decode(@payload,  @params[:rsa_public], true, { algorithm: @params[:alg] }).first
    rescue JWT::ExpiredSignature => e
      raise JwtValidatior::Exceptions::ExpiredToken, e
    rescue JWT::DecodeError => e
      raise JwtValidatior::Exceptions::IvalidToken, e
    end
  end
end
end
