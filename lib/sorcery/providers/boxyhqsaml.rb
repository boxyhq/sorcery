module Sorcery
  module Providers
    # This class adds support for OAuth with BoxyHQ SAML.
    #
    #   config.boxyhqsaml.site = <http://localhost:5225>
    #   config.boxyhqsaml.key = <key>
    #   config.boxyhqsaml.secret = <secret>
    #   ...
    #
    class Boxyhqsaml < Base
      include Protocols::Oauth2

      attr_accessor :auth_url, :token_url, :user_info_url

      def initialize
        super

        @site          = 'http://localhost:5225'
        @auth_url      = '/api/oauth/authorize'
        @token_url     = '/api/oauth/token'
        @user_info_url = '/api/oauth/userinfo'
        @state         = SecureRandom.hex(16)
      end

      def get_user_hash(access_token)
        response = access_token.get(site + user_info_url)

        auth_hash(access_token).tap do |h|
          h[:user_info] = JSON.parse(response.body)
          h[:uid] = h[:user_info]['id']
        end
      end

      # calculates and returns the url to which the user should be redirected,
      # to get authenticated at the external provider's site.
      def login_url(_params, _session)
        authorize_url(authorize_url: auth_url)
      end

      # tries to login the user from access token
      def process_callback(params, _session)
        args = {}.tap do |a|
          a[:code] = params[:code] if params[:code]
        end

        get_access_token(args, token_url: token_url, token_method: :post)
      end
    end
  end
end
