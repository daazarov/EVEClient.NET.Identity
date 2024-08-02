using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Stores;
using EVEClient.NET.Identity.Validators;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Claims;

namespace EVEClient.NET.Identity.Services
{
    public abstract class SignInPostOAuthBehavior : PostOAuthBehavior
    {
        private readonly IRequiredClaimsValidator _requiredClaimsValidator;
        private readonly IRemoteTokensHandler _remoteTokensHandler;

        private Task? _signInTask = null!;

        /// <summary>
        /// Gets the <see cref="IUserSession"/>
        /// </summary>
        protected readonly IUserSession UserSession;

        /// <summary>
        /// Gets the <see cref="IAccessTokenStore"/>
        /// </summary>
        protected readonly IAccessTokenStore AccessTokenStore;

        /// <summary>
        /// Gets the <see cref="IRefreshTokenStore"/>
        /// </summary>
        protected readonly IRefreshTokenStore RefreshTokenStore;

        /// <summary>
        /// Gets or sets the <see cref="AuthenticationScheme"/> asssociated with internal EVE authentication handler.
        /// </summary>
        protected AuthenticationScheme Scheme { get; private set; } = default!;

        public SignInPostOAuthBehavior(
            ILogger<PostOAuthBehavior> logger,
            IUserSession userSession,
            IOptionsMonitor<EveAuthenticationOAuthOptions> options,
            IRemoteTokensHandler remoteTokensHandler,
            IAccessTokenStore accessTokenStore,
            IRefreshTokenStore refreshTokenStore,
            IRequiredClaimsValidator requiredClaimsValidator) : base(logger, options)
        {
            ArgumentNullException.ThrowIfNull(userSession);
            ArgumentNullException.ThrowIfNull(requiredClaimsValidator);

            UserSession = userSession;
            AccessTokenStore = accessTokenStore;
            RefreshTokenStore = refreshTokenStore;

            _requiredClaimsValidator = requiredClaimsValidator;
            _remoteTokensHandler = remoteTokensHandler;
        }

        protected abstract Task<IEnumerable<Claim>> CreateUserClaimsAsync(OAuthClaimsContext context);

        protected abstract Task HandleOAuthTokensAsync(OAuthTokensContext context);

        protected abstract Task<ClaimsIdentity> CreateClaimsIdentityAsync();

        protected abstract Task<ClaimsPrincipal> CreateClaimsPrincipalAsync(ClaimsIdentityContext context);

        public override async Task InitializeAsync(AuthenticateResult externalAuthenticateResult, HttpContext context)
        {
            await base.InitializeAsync(externalAuthenticateResult, context);

            Scheme = await context.GetEveCookieAuthenticationScheme();
        }

        protected override async Task<PostOAuthBehaviorResult> HandleRemoteAuthenticationResult()
        {
            var sessionId = string.Empty;

            var currentUser = await UserSession.GetCurrentUserAsync();
            if (currentUser != null && 
                currentUser.GetEveSubject().EnshureEveSubjectNormalized() == OAuthPrincipal.GetEveSubject().EnshureEveSubjectNormalized())
            {
                sessionId = (await UserSession.GetCurrentSessionIdAsync())!;
            }
            else
            {
                sessionId = await UserSession.GenerateSessionIdAsync();
            }

            var signInContext = SignInBehaviorContext.Initialize(sessionId, new AuthenticationProperties());

            var handleResult = await HandleSingInAsync(signInContext);
            if (handleResult.Succeeded)
            {
                var tokensContext = new OAuthTokensContext(signInContext, handleResult.Principal, OAuthTokens);

                await HandleOAuthTokensAsync(tokensContext);
            }

            return handleResult;
        }

        protected async Task<PostOAuthSingInBehaviorResult> HandleSingInAsync(SignInBehaviorContext context)
        {
            var identity = await CreateClaimsIdentityAsync();
            if (identity == null)
            {
                return PostOAuthSingInBehaviorResult.Failed(new InvalidOperationException("Created application identity can not be null."));
            }

            var oauthClaims = ExtractExternalClaims(OAuthPrincipal);
            var oauthClaimsContext = new OAuthClaimsContext(context, oauthClaims.ToArray());

            var claims = await CreateUserClaimsAsync(oauthClaimsContext);

            var claimValidationResult = _requiredClaimsValidator.Validate(claims);
            if (!claimValidationResult.Succeeded)
            {
                return PostOAuthSingInBehaviorResult.Failed(new InvalidOperationException(claimValidationResult.Error));
            }

            identity.AddClaims(claims.Distinct(new ClaimComparer()));

            var identityContext = new ClaimsIdentityContext(context, identity);

            var principal = await CreateClaimsPrincipalAsync(identityContext);
            if (principal == null)
            {
                return PostOAuthSingInBehaviorResult.Failed(new InvalidOperationException("Created application principal can not be null."));
            }

            await SignInOnceAsync(principal, context.AuthenticationProperties);

            return PostOAuthSingInBehaviorResult.Success(principal, context.AuthenticationProperties);
        }

        /// <summary>
        /// Initializes a new task with deferred execution.
        /// If the method is called more than once, each time the old task will be replaced by a new one.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/></param>
        /// <param name="properties">The <see cref="AuthenticationProperties"/></param>
        /// <remarks>By default, the task is invoked when the <c>HandleSuccessfullBehaviorResult</c> method is processed.</remarks>
        protected Task SignInOnceAsync(ClaimsPrincipal principal, AuthenticationProperties properties)
        {
            ArgumentNullException.ThrowIfNull(principal);
            ArgumentNullException.ThrowIfNull(properties);

            var localPrincipal = principal;
            var localProperties = properties;
            var localSchemeName = Scheme.Name;

            if (_signInTask != null)
            {
                _signInTask.Dispose();
            }
            _signInTask = new Task(async () =>
            {
                await UserSession.InitializeSessionAsync(localPrincipal, localProperties);
                await Context.SignInAsync(localSchemeName, principal, properties);
            });

            return Task.CompletedTask;
        }

        protected virtual IEnumerable<Claim> ExtractExternalClaims(ClaimsPrincipal externalPrincipal)
        {
            var claims = new List<Claim>()
            {
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.Subject),
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.Name),
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.Owner),
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.Issuer),
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.AuthrizedParty),
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.Expiration),
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.IssuedAt),
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.JwtId),
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.KeyId),
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.Region),
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.Tenant),
                ExtractClaim(externalPrincipal.Claims, EveClaims.Issuers.Tier)
            };

            var scopes = ExtractClaims(externalPrincipal.Claims, EveClaims.Issuers.Scope);
            if (scopes.Any())
            {
                claims.AddRange(scopes);
            }
            else
            {
                claims.Add(new Claim(EveClaims.Issuers.Scope, string.Empty, ClaimValueTypes.String, ClaimsIssuer));
            }

            var audiences = ExtractClaims(externalPrincipal.Claims, EveClaims.Issuers.Audience);
            if (audiences.Any())
            {
                claims.AddRange(audiences);
            }

            return claims;
        }


        protected override async Task HandleSuccessfullBehaviorResult(PostOAuthBehaviorResult result)
        {
            if (_signInTask != null)
            {
                _signInTask.Start();
                await _signInTask;
            }
            
            // Clear external cookies
            await Context.SignOutAsync((await Context.GetEveCookieExternalAuthenticationScheme()).Name);

            var returnUrl = OAuthAuthenticateResult.Properties?.Items["returnUrl"] ?? "~/";

            Context.Response.Redirect(returnUrl);
        }

        protected override async Task HandleErrors(PostOAuthBehaviorResult result)
        {
            Logger.LogError(result.Error, "Failed to SignIn using authentication scheme: {schemeName}; OAuth Authentication result: {authResult}; OAuth tokens provided: {tokensProvided}",
                Scheme.Name, OAuthAuthenticateResult.Succeeded, OAuthTokens?.Any());

            // clean the tails
            await Context.SignOutAsync((await Context.GetEveCookieExternalAuthenticationScheme()).Name);
            await Context.SignOutAsync((await Context.GetEveCookieAuthenticationScheme()).Name);

            if (OAuthTokens != null && OAuthTokens.Any(x => x.Name == "refresh_token"))
            {
                await _remoteTokensHandler.RevokeRemoteToken("refresh_token", OAuthTokens.First(x => x.Name == "refresh_token").Value);
            }

            if (Options.OAuthFalurePath.HasValue)
            {
                Context.Response.Redirect(Options.OAuthFalurePath);
            }
            else
            {
                Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;

                await Context.Response.WriteAsync($"Failed to SignIn using authentication scheme: {Scheme.Name}");
                await Context.Response.StartAsync();
            }
        }

        private Claim ExtractClaim([NotNull] IEnumerable<Claim> claims, [NotNull] string claimType)
        {
            var claim = claims.FirstOrDefault(x => x.Type == claimType);

            if (claim is null)
            {
                throw new ArgumentNullException($"The claim with type [{claimType}] is missing from the EVE Online JWT.");
            }

            return claim;
        }

        private IEnumerable<Claim> ExtractClaims([NotNull] IEnumerable<Claim> claims, [NotNull] string claimType)
        {
            return claims.Where(x => x.Type == claimType).ToList();
        }
    }
}
