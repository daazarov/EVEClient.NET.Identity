using EVEClient.NET.Configuration;
using EVEClient.NET.Identity.Defaults;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Configuration
{
    public class EveAuthenticationOAuthOptions : OAuthOptions
    {
        public string RevokeTokenEndpoint { get; private set; } = default!;

        public string DiscoveryWebKeysEndpoint { get; private set; } = default!;

        public PathString OAuthFalurePath { get; set; }

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
