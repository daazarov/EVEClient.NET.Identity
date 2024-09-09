using System.Security.Claims;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Validators;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultSignInPostOAuthBehavior : BaseSignInPostOAuthBehavior
    {
        /// <summary>
        /// Gets the collection of <see cref="IUserClaimsTransformator"/>
        /// </summary>
        protected IEnumerable<IUserClaimsTransformator> ClaimsTransformations { get; }

        /// <summary>
        /// Gets the <see cref="EveAuthenticationOptions"/>.
        /// </summary>
        protected EveAuthenticationOptions Options { get; }

        public DefaultSignInPostOAuthBehavior(
            ILogger<BasePostOAuthBehavior> logger,
            IUserSession userSession,
            IOptionsMonitor<EveAuthenticationOAuthOptions> oauthOptions,
            IOptionsMonitor<EveAuthenticationOptions> options,
            ITokenHandlerProvider tokenHandlerProvider,
            IRequiredClaimsValidator requiredClaimsValidator,
            IEnumerable<IUserClaimsTransformator> claimsTransformations)
            : base(logger, userSession, oauthOptions, tokenHandlerProvider, requiredClaimsValidator)
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

        protected override async Task HandleOAuthTokensAsync(PostOAuthSingInBehaviorResult result, OAuthTokensContext context)
        {
            if (!result.Succeeded) return;

            var accessTokenHandler = await TokenHandlerProvider.GetAccessTokenHandler(HttpContext, Scheme.Name);
            if (accessTokenHandler != null && accessTokenHandler is IStoreTokenHandler<AccessTokenStoreRequest> storeHandler)
            {
                // singin procces is not completed yet, so initialize with prepared authentication context manualy
                await accessTokenHandler.InitializeAsync(HttpContext, result.Principal, result.AuthenticationProperties);

                await storeHandler.StoreTokensAsync(new AccessTokenStoreRequest
                {
                    SubjectId = SubjectId,
                    AccessToken = context.AccessToken,
                    RefreshToken = context.RefreshToken,
                    IssuedAt = context.IssuedAt,
                    ExpiresAt = context.ExpiresAt,
                    GrantedScopes = [.. context.Scopes]
                });
            }
            else
            {
                Logger.LogWarning(
                    "Access token handler don't realize IStoreTokenHandler interface " +
                    "or no access token handler is configured to request for the scheme: {authenticationScheme}. " +
                    "The tokens will not be saved in the storage.", Scheme.Name);
            }
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
