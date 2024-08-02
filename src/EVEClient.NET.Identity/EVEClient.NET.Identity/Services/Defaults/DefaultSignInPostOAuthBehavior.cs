using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Stores;
using EVEClient.NET.Identity.Validators;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultSignInPostOAuthBehavior : SignInPostOAuthBehavior
    {
        /// <summary>
        /// Gets the collection of <see cref="IUserClaimsTransformator"/>
        /// </summary>
        protected readonly IEnumerable<IUserClaimsTransformator> ClaimsTransformations;

        public DefaultSignInPostOAuthBehavior(
            ILogger<PostOAuthBehavior> logger,
            IUserSession userSession,
            IOptionsMonitor<EveAuthenticationOAuthOptions> options,
            IRemoteTokensHandler remoteTokensHandler,
            IAccessTokenStore accessTokenStore,
            IRefreshTokenStore refreshTokenStore,
            IRequiredClaimsValidator requiredClaimsValidator,
            IEnumerable<IUserClaimsTransformator> claimsTransformations)
            : base(logger, userSession, options, remoteTokensHandler, accessTokenStore, refreshTokenStore, requiredClaimsValidator)
        {
            ClaimsTransformations = claimsTransformations;
        }

        protected override Task<ClaimsIdentity> CreateClaimsIdentityAsync()
        {
            return Task.FromResult(new ClaimsIdentity(EveConstants.AuthenticationType, EveClaims.Issuers.Name, null));
        }

        protected override Task<ClaimsPrincipal> CreateClaimsPrincipalAsync(ClaimsIdentityContext context)
        {
            return Task.FromResult(new ClaimsPrincipal(context.Identity));
        }

        protected override async Task<IEnumerable<Claim>> CreateUserClaimsAsync(OAuthClaimsContext context)
        {
            var issuedClaims = new List<Claim>
            {
                context.OAuthClaims.First(x => x.Type == EveClaims.Issuers.Name),
                context.OAuthClaims.First(x => x.Type == EveClaims.Issuers.Subject),
                context.OAuthClaims.First(x => x.Type == EveClaims.Issuers.IssuedAt),
                context.OAuthClaims.First(x => x.Type == EveClaims.Issuers.Expiration),
            };

            issuedClaims.AddRange(context.OAuthClaims.Where(x => x.Type == EveClaims.Issuers.Scope));
            issuedClaims.AddRange(context.OAuthClaims.Where(x => GetOptionalIssuerClaimNames().Contains(x.Type)));

            var claimContext = new ClaimsTransformationContext(issuedClaims, ClaimsIssuer, OAuthTokens, context.OAuthClaims);
            await TransformClaimsAsync(claimContext);

            return claimContext.IssuedClaims;
        }

        protected override async Task HandleOAuthTokensAsync(OAuthTokensContext context)
        {
            var accessToken = new AccessTokenData
            {
                SubjectId = context.SubjectId,
                TokenType = "access_token",
                Value = context.AccessToken,
                GrantedScopes = context.Scopes.ToList(),
                CreationTime = context.IssuedAt,
                ExpiresAt = context.ExpiresAt,
                SessionId = context.SessionId,
            };

            var refreshToken = new RefreshTokenData
            {
                SubjectId = context.SubjectId,
                TokenType = "refresh_token",
                Value = context.RefreshToken,
                SessionId = context.SessionId,
                CreationTime = context.IssuedAt,
            };

            var accessTokenKey = await AccessTokenStore.StoreAccessTokenAsync(accessToken);
            var refreshTokenKey = await RefreshTokenStore.StoreRefreshTokenAsync(refreshToken);

            if (accessTokenKey.IsMissing() || refreshTokenKey.IsMissing())
            {
                throw new InvalidOperationException("Access and Resfresh token reference key can not be null or empty.");
            }

            context.AuthenticationProperties.StoreEveAccessTokenReferenceKey(accessTokenKey);
            context.AuthenticationProperties.StoreEveRefreshTokenReferenceKey(refreshTokenKey);

            await SignInOnceAsync(context.Principal, context.AuthenticationProperties);
        }

        protected virtual async Task TransformClaimsAsync(ClaimsTransformationContext context)
        {
            foreach (var transformation in ClaimsTransformations.OrderBy(x => x.Order))
            {
                await transformation.TransformAsync(context);
            }
        }

        protected virtual IEnumerable<string> GetOptionalIssuerClaimNames()
        {
            return new List<string>
            {
                EveClaims.Issuers.Region,
                EveClaims.Issuers.Issuer,
                EveClaims.Issuers.JwtId,
                EveClaims.Issuers.Owner,
                EveClaims.Issuers.Tier,
                EveClaims.Issuers.Tenant,
                EveClaims.Issuers.AuthrizedParty,
                EveClaims.Issuers.Audience,
                EveClaims.Issuers.KeyId
            };
        }
    }
}
