using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;

using EVEClient.NET.Configuration;
using EVEClient.NET.Identity.Defaults;

namespace EVEClient.NET.Identity.Configuration
{
    public class EveAuthenticationOAuthOptions : OAuthOptions
    {
        /// <summary>
        /// Gets the ESI SSO endpoint that allows revoking refresh token.
        /// </summary>
        public string RevokeTokenEndpoint { get; private set; } = default!;

        /// <summary>
        /// Gets the ESI SSO endpoint that retrieve metadata about SSO server.
        /// </summary>
        public string DiscoveryWebKeysEndpoint { get; private set; } = default!;

        /// <summary>
        /// Gets or sets path to redirect in case of unsuccessful OAuth authentication. If not specified, the general error will be display.
        /// </summary>
        public PathString OAuthFailurePath { get; set; }

        /// <summary>
        /// Sets the server to be authenticated.
        /// </summary>
        public EVEOnlineServer Server
        {
            set
            {
                switch (value)
                {
                    case EVEOnlineServer.Tranquility:
                        AuthorizationEndpoint = EveOAuthEndpointDefaults.Tranquility.AuthorizationEndpoint;
                        TokenEndpoint = EveOAuthEndpointDefaults.Tranquility.TokenEndpoint;
                        RevokeTokenEndpoint = EveOAuthEndpointDefaults.Tranquility.RevokeTokenEndpoint;
                        ClaimsIssuer = EveOAuthEndpointDefaults.Tranquility.Issuer;
                        DiscoveryWebKeysEndpoint = EveOAuthEndpointDefaults.Tranquility.DiscoveryWebKeysEndpoint;
                        break;
                    case EVEOnlineServer.Singularity:
                        AuthorizationEndpoint = EveOAuthEndpointDefaults.Singularity.AuthorizationEndpoint;
                        TokenEndpoint = EveOAuthEndpointDefaults.Singularity.TokenEndpoint;
                        RevokeTokenEndpoint = EveOAuthEndpointDefaults.Singularity.RevokeTokenEndpoint;
                        ClaimsIssuer = EveOAuthEndpointDefaults.Singularity.Issuer;
                        DiscoveryWebKeysEndpoint = EveOAuthEndpointDefaults.Singularity.DiscoveryWebKeysEndpoint;
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(EVEOnlineServer));
                }
            }
        }
    }
}
