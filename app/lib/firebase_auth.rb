#  Usage:
# ========
#   FirebaseAuth::Auth.verify_id_token(your_id_token)
#
#  Dependencies:
# ---------------
#   gem 'activesupport'
#   gem 'faraday'
#   gem 'jwt', '~> 1.5', '>= 1.5.6'

# require 'jwt'
# require 'faraday'
# require 'active_support/core_ext/module/delegation'
#
# require 'openssl'
# require 'singleton'
# require 'ostruct'

module FirebaseAuth
  class PublicKeys
    URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
    EXPIRES_HEADER = "expires"

    attr_reader :response

    delegate :keys, :values, to: :data

    def initialize
      @response = fetch
    end

    def valid?
      Time.now.utc < time_to_expire
    end

    def data
      @parsed_body ||= JSON.parse(response.body)
    end

    def look_up(kid)
      @certificate_hash ||= Hash[data.map { |k, v| [k, OpenSSL::X509::Certificate.new(v)] }]
      @certificate_hash[kid]
    end

    private

    def time_to_expire
      @time_to_expire ||= Time.parse(
        response.headers[EXPIRES_HEADER]
      )
    end

    def fetch
      Faraday.get(URL)
    end
  end

  class IDTokenVerifier
    JWT_OPTIONS = {algorithm: "RS256", verify_iat: true}

    def initialize(public_keys)
      @public_keys = public_keys
    end

    def verify(id_token)
      kid = JWT.decode(id_token, nil, false).last["kid"] rescue nil
      decode_jwt(id_token, @public_keys.look_up(kid)) rescue nil
    end

    private

    def decode_jwt(id_token, x509)
      JWT.decode(id_token, x509.public_key, true, JWT_OPTIONS)
    rescue JWT::VerificationError
      nil
    end
  end

  class Auth
    include Singleton

    def initialize
      refresh
    end

    def public_keys
      resolve { @public_keys }
    end

    def verify_id_token(id_token)
      result = resolve { @id_token_verifier.verify(id_token) }
      if result
        payload, header = result
        [OpenStruct.new(payload), OpenStruct.new(header)]
      end
    end

    class << self
      delegate :verify_id_token, :public_keys, to: :instance
    end

    private

    def refresh
      @public_keys = PublicKeys.new
      @id_token_verifier = IDTokenVerifier.new(@public_keys)
    end

    def resolve
      refresh unless @public_keys.valid?

      yield
    end
  end
end
