using System.Diagnostics.CodeAnalysis;
using System.Text;

using Microsoft.AspNetCore.Authentication;

using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.OAuth
{
    public class RefreshAccessTokenResponse : OAuthResponse
    {
        /// <summary>
        /// Gets the access token.
        /// </summary>
        public string? AccessToken { get; }

        /// <summary>
        /// Gets the refresh token.
        /// </summary>
        public string? RefreshToken { get; }

        /// <summary>
        /// Gets the expires_in value (seconds in unix timestamp).
        /// </summary>
        public string? ExpiresIn { get; }

        /// <summary>
        /// Gets the token type.
        /// </summary>
        public string? TokenType { get; }

        [MemberNotNullWhen(true, nameof(AccessToken), nameof(RefreshToken), nameof(ExpiresIn))]
        public override bool IsSuccessed => base.IsSuccessed && AccessToken.IsPresent() && RefreshToken.IsPresent() && ExpiresIn.IsPresent();

        public RefreshAccessTokenResponse(HttpResponseMessage httpResponseMessage, string bodyResponse) : base(httpResponseMessage, bodyResponse)
        {
            var root = JsonResponse.RootElement;

            AccessToken = root.GetString("access_token");
            TokenType = root.GetString("token_type");
            RefreshToken = root.GetString("refresh_token");
            ExpiresIn = root.GetString("expires_in");
        }
    }
}
