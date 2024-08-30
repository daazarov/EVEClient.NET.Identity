namespace EVEClient.NET.Identity.OAuth
{
    public static class HttpClientExtensions
    {
        /// <summary>
        /// Sends a token request using the refresh_token grant type.
        /// </summary>
        /// <param name="client">The <see cref="HttpClient"/>.</param>
        /// <param name="request">The <see cref="RefreshAccessTokenRequest"/> request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public static async Task<RefreshAccessTokenResponse> RefreshAccessTokenAsync(this HttpClient client, RefreshAccessTokenRequest request, CancellationToken cancellationToken = default)
        {
            request.Parameters.Add(OAuthConstants.TokenRequest.RefreshToken, request.RefreshToken);
            request.Parameters.Add(OAuthConstants.TokenRequest.GrantType, OAuthConstants.TokenTypes.RefreshToken);

            if (request.Scopes?.Any() == true)
            {
                request.Parameters.Add(OAuthConstants.TokenRequest.Scope, string.Join(" ", request.Scopes));
            }

            var response = await client.SendTokenRequestAsync(request, cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync();

            return new RefreshAccessTokenResponse(response, responseBody);
        }

        /// <summary>
        /// Sends an OAuth token revocation request.
        /// </summary>
        /// <param name="client">The <see cref="HttpClient"/>.</param>
        /// <param name="request">The <see cref="RevokeRefreshTokenRequest"/> request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public static async Task<OAuthResponse> RevokeRefreshTokenAsync(this HttpClient client, RevokeRefreshTokenRequest request, CancellationToken cancellationToken = default)
        {
            request.Parameters.Add(OAuthConstants.TokenRequest.Token, request.RefreshToken);
            request.Parameters.Add(OAuthConstants.TokenRequest.TokenTypeHint, OAuthConstants.TokenTypes.RefreshToken);

            var response = await client.SendTokenRequestAsync(request, cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync();

            return new OAuthResponse(response, responseBody);
        }


        public static async Task<HttpResponseMessage> SendTokenRequestAsync(this HttpClient client, OAuthRequest request, CancellationToken cancellationToken = default)
        {
            request.Prepare();

            return await client.SendAsync(request, cancellationToken);
        }
    }
}
