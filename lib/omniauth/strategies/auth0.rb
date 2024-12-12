module OmniAuth
  module Strategies
    # Auth0 OmniAuth strategy
    class Auth0 < OmniAuth::Strategies::OAuth2
      include OmniAuth::Auth0::Telemetry

      option :name, 'auth0'
      args %i[client_id client_secret domain]

      # Logger
      logger = Logger.new(STDOUT)
      logger.level = Logger::DEBUG

      # Setup client URLs used during authentication
      def client
        logger.debug("Configuring client URLs with domain: #{domain_url}")
        options.client_options.site = domain_url
        options.client_options.authorize_url = '/authorize'
        options.client_options.token_url = '/oauth/token'
        options.client_options.userinfo_url = '/userinfo'
        super
      end

      # Use the "sub" key of the userinfo returned as the uid (globally unique string identifier).
      uid {
        logger.debug("UID extracted: #{raw_info['sub']}")
        raw_info['sub']
      }

      # Build the API credentials hash with returned auth data.
      credentials do
        logger.debug("Building credentials for access_token: #{access_token.token}")
        credentials = { 'token' => access_token.token, 'expires' => true }

        if access_token.params
          credentials.merge!(
            'id_token' => access_token.params['id_token'],
            'token_type' => access_token.params['token_type'],
            'refresh_token' => access_token.refresh_token
          )
        end

        # Log session and token verification
        session_authorize_params = session['authorize_params'] || {}
        session.delete('authorize_params')
        auth_scope = session_authorize_params[:scope]
        if auth_scope.respond_to?(:include?) && auth_scope.include?('openid')
          logger.debug("Verifying ID token: #{credentials['id_token']}")
          jwt_validator.verify(credentials['id_token'], session_authorize_params)
        end

        credentials
      end

      # Store all raw information for use in the session.
      extra do
        logger.debug("Storing raw info: #{raw_info}")
        { raw_info: raw_info }
      end

      # Build a hash of information about the user with keys taken from the Auth Hash Schema.
      info do
        logger.debug("User info: #{raw_info}")
        {
          name: raw_info['name'] || raw_info['sub'],
          nickname: raw_info['nickname'],
          email: raw_info['email'],
          image: raw_info['picture']
        }
      end

      # Define the parameters used for the /authorize endpoint
      def authorize_params
        params = super
        %w[connection connection_scope prompt screen_hint login_hint organization invitation ui_locales].each do |key|
          params[key] = request.params[key] if request.params.key?(key)
        end

        # Generate nonce
        params[:nonce] = SecureRandom.hex
        params[:leeway] = 60 unless params[:leeway]

        # Log authorization parameters
        logger.debug("Authorization params: #{params}")

        # Store authorize params in the session for token verification
        session['authorize_params'] = params.to_hash
        params
      end

      def build_access_token
        logger.debug("Building access token with telemetry header")
        options.token_params[:headers] = { 'Auth0-Client' => telemetry_encoded }
        super
      end

      # Declarative override for the request phase of authentication
      def request_phase
        if no_client_id?
          logger.error("Missing client_id")
          fail!(:missing_client_id)
        elsif no_client_secret?
          logger.error("Missing client_secret")
          fail!(:missing_client_secret)
        elsif no_domain?
          logger.error("Missing domain")
          fail!(:missing_domain)
        else
          logger.debug("Running OAuth2 request phase")
          super
        end
      end

      def callback_phase
        logger.debug("Entering callback phase")
        super
      rescue OmniAuth::Auth0::TokenValidationError => e
        logger.error("Token validation error: #{e.message}")
        fail!(:token_validation_error, e)
      end

      private

      def jwt_validator
        @jwt_validator ||= OmniAuth::Auth0::JWTValidator.new(options)
      end

      # Parse the raw user info.
      def raw_info
        return @raw_info if @raw_info

        if access_token["id_token"]
          logger.debug("Decoding JWT ID Token")
          claims, header = jwt_validator.decode(access_token["id_token"])
          @raw_info = claims
        else
          logger.debug("Fetching userinfo from #{options.client_options.userinfo_url}")
          userinfo_url = options.client_options.userinfo_url
          @raw_info = access_token.get(userinfo_url).parsed
        end

        logger.debug("Raw info: #{@raw_info}")
        @raw_info
      end

      # Check if the options include a client_id
      def no_client_id?
        ['', nil].include?(options.client_id)
      end

      # Check if the options include a client_secret
      def no_client_secret?
        ['', nil].include?(options.client_secret)
      end

      # Check if the options include a domain
      def no_domain?
        ['', nil].include?(options.domain)
      end

      # Normalize a domain to a URL.
      def domain_url
        domain_url = URI(options.domain)
        domain_url = URI("https://#{domain_url}") if domain_url.scheme.nil?
        domain_url.to_s
      end
    end
  end
end
