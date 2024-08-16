using System.Net.Http.Headers;
using System.Text.Json;
using System.Text;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

using EVEClient.NET.Identity.Stores;
using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Defaults;

using Newtonsoft.Json;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultRemoteTokensHandler : IRemoteTokensHandler
    {
        private readonly ILogger<PostOAuthBehavior> _logger;
        private readonly IAccessTokenStore _accessTokenStore;
        private readonly IRefreshTokenStore _refreshTokenStore;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IOptionsMonitor<EveAuthenticationOAuthOptions> _options;

        private HttpClient Backchannel => _httpClientFactory.CreateClient(EveConstants.SsoHttpClientName);
        private EveAuthenticationOAuthOptions Options => _options.Get(EveAuthenticationCookieDefaults.OAuth.DefaultOAuthAuthenticationSchemeName);

        public DefaultRemoteTokensHandler(
            ILogger<PostOAuthBehavior> logger,
            IAccessTokenStore accessTokenStore,
            IRefreshTokenStore refreshTokenStore,
            IHttpClientFactory httpClientFactory,
            IOptionsMonitor<EveAuthenticationOAuthOptions> options)
        { 
            _logger = logger;
            _accessTokenStore = accessTokenStore;
            _refreshTokenStore = refreshTokenStore;
            _httpClientFactory = httpClientFactory;
            _options = options;
        }

        public async Task<OAuthTokenResponse> RenewAccessToken(string refreshToken)
        {
            var parameters = new Dictionary<string, string>()
            {
                { "refresh_token", refreshToken },
                { "grant_type", "refresh_token" },
            };

            var requestContent = new FormUrlEncodedContent(parameters);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;

            SetupAuthenticationHeaderValue(requestMessage);

            var response = await Backchannel.SendAsync(requestMessage);
            var body = await response.Content.ReadAsStringAsync();

            return response.IsSuccessStatusCode switch
            {
                true => OAuthTokenResponse.Success(JsonDocument.Parse(body)),
                false => PrepareFailedOAuthTokenReponse(response, body)
            };
        }

        public async Task RevokeRemoteToken(string tokenType, string token)
        {
            var parameters = new Dictionary<string, string>()
            {
                { "token", token },
                { "token_type_hint", tokenType },
            };

            var requestContent = new FormUrlEncodedContent(parameters);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.RevokeTokenEndpoint);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;

            SetupAuthenticationHeaderValue(requestMessage);

            var result = await Backchannel.SendAsync(requestMessage);
        }

        private void SetupAuthenticationHeaderValue(HttpRequestMessage request)
        {
            ArgumentNullException.ThrowIfNull(request);

            var byteArray = Encoding.ASCII.GetBytes(Options.ClientId + ":" + Options.ClientSecret);

            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));
        }

        private static OAuthTokenResponse PrepareFailedOAuthTokenReponse(HttpResponseMessage response, string body)
        {
            var errorBody = JsonConvert.DeserializeAnonymousType(body, new { error = string.Empty, error_description = string.Empty });

            if (errorBody == null || (errorBody.error.IsMissing() && errorBody.error_description.IsMissing()))
            {
                var errorMessage = $"OAuth token endpoint failure. Status: {response.StatusCode}; Headers: {response.Headers}; Body: {body};";
                return OAuthTokenResponse.Failed(new AuthenticationFailureException(errorMessage));
            }

            return OAuthTokenResponse.Failed(new AuthenticationFailureException($"Error: {errorBody.error}; Error Description: {errorBody.error_description}"));
        }
    }
}
