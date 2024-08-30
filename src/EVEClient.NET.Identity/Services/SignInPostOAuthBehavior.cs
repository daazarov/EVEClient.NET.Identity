using System.Net;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Stores;
using EVEClient.NET.Identity.Validators;

namespace EVEClient.NET.Identity.Services
{
    public abstract class SignInPostOAuthBehavior : PostOAuthBehavior
    {
        private readonly IRequiredClaimsValidator _requiredClaimsValidator;
        private readonly ITokenHandlerProvider _tokenHandlerProvider;

        private Task? _signInTask = null;

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
            ITokenHandlerProvider tokenHandlerProvider,
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
            _tokenHandlerProvider = tokenHandlerProvider;
        }

        protected abstract Task<IEnumerable<Claim>> CreateUserClaimsAsync(OAuthClaimsContext context);

        protected abstract Task HandleOAuthTokensAsync(OAuthTokensContext context);

        protected abstract Task<ClaimsIdentity> CreateClaimsIdentityAsync();

        protected abstract Task<ClaimsPrincipal> CreateClaimsPrincipalAsync(ClaimsIdentityContext context);

        public sealed override async Task InitializeAsync(AuthenticateResult externalAuthenticateResult, HttpContext context)
        {
            await base.InitializeAsync(externalAuthenticateResult, context);

            Scheme = await context.GetEveCookieAuthenticationScheme();
        }

        protected sealed override async Task<PostOAuthBehaviorResult> HandleRemoteAuthenticationResult()
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

            _signInTask = new Task(async () =>
            {
                await UserSession.InitializeSessionAsync(localPrincipal, localProperties);
                await Context.SignInAsync(localSchemeName, localPrincipal, localProperties);
            });

            return Task.CompletedTask;
        }

        protected sealed override async Task HandleSuccessfullBehaviorResult(PostOAuthBehaviorResult result)
        {
            if (_signInTask != null)
            {
                _signInTask.Start();
                await _signInTask;
            }
            else
            {
                throw new InvalidOperationException("SignInOnceAsync must be called at least once.");
            }

            // Clear external cookies
            await Context.SignOutAsync((await Context.GetEveCookieExternalAuthenticationScheme()).Name);

            await HandleCompletionAsync();
        }

        protected override async Task HandleErrors(PostOAuthBehaviorResult result)
        {
            Logger.LogError(result.Error, "Failed to SignIn using authentication scheme: {schemeName}; OAuth Authentication result: {authResult}; OAuth tokens provided: {tokensProvided}",
                Scheme.Name, OAuthAuthenticateResult.Succeeded, OAuthTokens?.Any() == true);

            // clean the tails
            await Context.SignOutAsync((await Context.GetEveCookieExternalAuthenticationScheme()).Name);
            await Context.SignOutAsync((await Context.GetEveCookieAuthenticationScheme()).Name);

            if (OAuthTokens != null && OAuthTokens.Any(x => x.Name == "refresh_token"))
            {
                var handler = await _tokenHandlerProvider.GetRefreshTokenHandler(Context, Scheme.Name, false);
                if (handler != null)
                {
                    await handler.RevokeToken(OAuthTokens.First(x => x.Name == "refresh_token").Value);
                }
            }

            if (OAuthOptions.OAuthFailurePath.HasValue)
            {
                Context.Response.Redirect(OAuthOptions.OAuthFailurePath);
            }
            else
            {
                Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;

                await Context.Response.WriteAsync($"Failed to SignIn using authentication scheme: {Scheme.Name}");
                await Context.Response.StartAsync();
            }
        }

        protected virtual Task HandleCompletionAsync()
        {
            var returnUrl = OAuthAuthenticateResult.Properties?.Items["returnUrl"];
            if (returnUrl.IsMissing())
            {
                returnUrl = "/";
            }

            Context.Response.Redirect(returnUrl);

            return Task.CompletedTask;
        }

        private IEnumerable<Claim> ExtractExternalClaims(ClaimsPrincipal externalPrincipal)
        {
            var claims = new List<Claim>();

            foreach (var externalClaim in externalPrincipal.Claims)
            {
                // unbind from external principal
                claims.Add(externalClaim.Clone());
            }

            if (!claims.Any(x => x.Type == EveClaims.Issuers.Scope))
            {
                claims.Add(new Claim(EveClaims.Issuers.Scope, string.Empty, ClaimValueTypes.String, ClaimsIssuer));
            }

            return claims;
        }
    }
}
