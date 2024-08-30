using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Stores;
using EVEClient.NET.Identity.Validators;

using System.Globalization;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultSignInPostOAuthBehavior : SignInPostOAuthBehavior
    {
        /// <summary>
        /// Gets the collection of <see cref="IUserClaimsTransformator"/>
        /// </summary>
        protected readonly IEnumerable<IUserClaimsTransformator> ClaimsTransformations;

        /// <summary>
        /// Gets the <see cref="EveAuthenticationOptions"/>.
        /// </summary>
        protected readonly EveAuthenticationOptions Options;

        public DefaultSignInPostOAuthBehavior(
            ILogger<PostOAuthBehavior> logger,
            IUserSession userSession,
            IOptionsMonitor<EveAuthenticationOAuthOptions> oauthOptions,
            IOptionsMonitor<EveAuthenticationOptions> options,
            ITokenHandlerProvider tokenHandlerProvider,
            IAccessTokenStore accessTokenStore,
            IRefreshTokenStore refreshTokenStore,
            IRequiredClaimsValidator requiredClaimsValidator,
            IEnumerable<IUserClaimsTransformator> claimsTransformations)
            : base(logger, userSession, oauthOptions, tokenHandlerProvider, accessTokenStore, refreshTokenStore, requiredClaimsValidator)
        {
            ClaimsTransformations = claimsTransformations;
            Options = options.CurrentValue;
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

            var optionalIsserClaimNames = GetOptionalIssuerClaimNames().ToArray();

            issuedClaims.AddRange(context.OAuthClaims.Where(x => x.Type == EveClaims.Issuers.Scope));
            issuedClaims.AddRange(context.OAuthClaims.Where(x => x.Type.In(optionalIsserClaimNames)));

            var claimContext = new ClaimsTransformationContext(issuedClaims, ClaimsIssuer, OAuthTokens, context.OAuthClaims);
            await TransformClaimsAsync(claimContext);

            return claimContext.IssuedClaims;
        }

        protected override async Task HandleOAuthTokensAsync(OAuthTokensContext context)
        {
            if (Options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>
                {
                    new AuthenticationToken { Name = "access_token", Value = context.AccessToken },
                    new AuthenticationToken { Name = "refresh_token", Value = context.RefreshToken },
                    new AuthenticationToken { Name = "expires_at", Value = context.ExpiresAt.ToString("o", CultureInfo.InvariantCulture) }
                };

                context.AuthenticationProperties.StoreTokens(authTokens);
            }

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

            await SignInOnceAsync(context.Principal, context.AuthenticationProperties);
        }

        protected virtual async Task TransformClaimsAsync(ClaimsTransformationContext context)
        {
            // The order is based on registration order and is guaranteed by Microsoft DI
            // https://learn.microsoft.com/en-us/aspnet/core/fundamentals/dependency-injection?view=aspnetcore-3.1#service-registration-methods-1
            foreach (var transformation in ClaimsTransformations)
            {
                await transformation.TransformAsync(context);
            }
        }

        protected virtual IEnumerable<string> GetOptionalIssuerClaimNames()
        {
            if (Options.IncludeIssuerClaims.IssuerEnable)
            { 
                yield return EveClaims.Issuers.Issuer;
            }
            if (Options.IncludeIssuerClaims.OwnerEnable)
            {
                yield return EveClaims.Issuers.Owner;
            }
            if (Options.IncludeIssuerClaims.RegionEnable)
            {
                yield return EveClaims.Issuers.Region;
            }
            if (Options.IncludeIssuerClaims.TenantEnable)
            {
                yield return EveClaims.Issuers.Tenant;
            }
            if (Options.IncludeIssuerClaims.KeyIdEnable)
            {
                yield return EveClaims.Issuers.KeyId;
            }
            if (Options.IncludeIssuerClaims.AudienceEnable)
            {
                yield return EveClaims.Issuers.Audience;
            }
            if (Options.IncludeIssuerClaims.AuthrizedPartyEnable)
            {
                yield return EveClaims.Issuers.AuthrizedParty;
            }
            if (Options.IncludeIssuerClaims.JwtIdEnable)
            {
                yield return EveClaims.Issuers.JwtId;
            }
            if (Options.IncludeIssuerClaims.TierEnable)
            {
                yield return EveClaims.Issuers.Tier;
            }
        }
    }
}
