using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text;

using Microsoft.AspNetCore.Authentication;
using Newtonsoft.Json;
using EVEClient.NET.Identity.Stores;
using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using Microsoft.Extensions.Logging;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultRemoteTokensHandler : IRemoteTokensHandler
    {
        private readonly ILogger<PostOAuthBehavior> _logger;
        private readonly IAccessTokenStore _accessTokenStore;
        private readonly IRefreshTokenStore _refreshTokenStore;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly EveAuthenticationOAuthOptions _options;

        private HttpClient Backchannel => _httpClientFactory.CreateClient(EveConstants.SsoHttpClientName);

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

            _options = options.CurrentValue;
        }

        public async Task<OAuthTokenResponse> RenewAccessToken(string refreshToken)
        {
            var parameters = new Dictionary<string, string>()
            {
                { "refresh_token", refreshToken },
                { "grant_type", "refresh_token" },
            };

            var requestContent = new FormUrlEncodedContent(parameters);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, _options.TokenEndpoint);
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
                { "refresh_token", token },
                { "token_type_hint", tokenType },
            };

            var requestContent = new FormUrlEncodedContent(parameters);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, _options.RevokeTokenEndpoint);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;

            SetupAuthenticationHeaderValue(requestMessage);

            await Backchannel.SendAsync(requestMessage);
        }

        private void SetupAuthenticationHeaderValue(HttpRequestMessage request)
        {
            ArgumentNullException.ThrowIfNull(request);

            var byteArray = Encoding.ASCII.GetBytes(_options.ClientId + ":" + _options.ClientSecret);

            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));
        }

        private static OAuthTokenResponse PrepareFailedOAuthTokenReponse(HttpResponseMessage response, string body)
        {
            var error = JsonConvert.DeserializeAnonymousType(body, new { error_description = string.Empty })?.error_description;

            if (error.IsMissing())
            {
                var errorMessage = $"OAuth token endpoint failure: Status: {response.StatusCode};Headers: {response.Headers};Body: {body};";
                return OAuthTokenResponse.Failed(new AuthenticationFailureException(errorMessage));
            }

            return OAuthTokenResponse.Failed(new AuthenticationFailureException(error));
        }
    }
}
