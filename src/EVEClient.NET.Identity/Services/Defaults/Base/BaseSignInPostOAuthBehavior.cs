using System.Net;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Validators;
using EVEClient.NET.Identity.OAuth;

namespace EVEClient.NET.Identity.Services
{
    public abstract class BaseSignInPostOAuthBehavior : BasePostOAuthBehavior
    {
        private readonly IRequiredClaimsValidator _requiredClaimsValidator;

        private Task? _signInTask = null;

        /// <summary>
        /// Gets the <see cref="IUserSession"/>
        /// </summary>
        protected IUserSession UserSession { get; }

        /// <summary>
        /// Gets the <see cref="ITokenHandlerProvider"/>
        /// </summary>
        protected ITokenHandlerProvider TokenHandlerProvider { get; }

        /// <summary>
        /// Gets or sets the <see cref="AuthenticationScheme"/> asssociated with internal EVE authentication handler.
        /// </summary>
        protected AuthenticationScheme Scheme { get; private set; } = default!;

        public BaseSignInPostOAuthBehavior(
            ILogger<BasePostOAuthBehavior> logger,
            IUserSession userSession,
            IOptionsMonitor<EveAuthenticationOAuthOptions> options,
            ITokenHandlerProvider tokenHandlerProvider,
            IRequiredClaimsValidator requiredClaimsValidator) : base(logger, options)
        {
            UserSession = userSession;

            _requiredClaimsValidator = requiredClaimsValidator;
            TokenHandlerProvider = tokenHandlerProvider;
        }

        /// <summary>
        /// Allows derived types to create user claims.
        /// </summary>
        /// <param name="context">The <see cref="OAuthClaimsContext"/>.</param>
        /// <returns>The <see cref="Claim"/> collection.</returns>
        protected abstract Task<IEnumerable<Claim>> CreateUserClaimsAsync(OAuthClaimsContext context);

        /// <summary>
        /// Allows derived types to handle OAuth tokens.
        /// </summary>
        /// <param name="context">The <see cref="OAuthTokensContext"/>.</param>
        /// <param name="result">The <see cref="PostOAuthSingInBehaviorResult"/>.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        /// <remarks> Called after a successful result of a <see cref="HandleSingInAsync(SignInBehaviorContext)"/> call.</remarks>
        protected abstract Task HandleOAuthTokensAsync(PostOAuthSingInBehaviorResult result, OAuthTokensContext context);

        /// <summary>
        /// Allows derived types to create claims identity.
        /// </summary>
        /// <returns>The <see cref="ClaimsIdentity"/>.</returns>
        protected abstract Task<ClaimsIdentity> CreateClaimsIdentityAsync();

        /// <summary>
        /// Allows derived types to create claims principal.
        /// </summary>
        /// <param name="context">The <see cref="ClaimsIdentityContext"/>.</param>
        /// <returns>The <see cref="ClaimsPrincipal"/>.</returns>
        protected abstract Task<ClaimsPrincipal> CreateClaimsPrincipalAsync(ClaimsIdentityContext context);

        public sealed override async Task InitializeAsync(AuthenticateResult externalAuthenticateResult, HttpContext context)
        {
            await base.InitializeAsync(externalAuthenticateResult, context);

            Scheme = await context.GetEveCookieAuthenticationScheme();

            HttpContext.Response.OnStarting(FinishResponseAsync);
        }

        protected override async Task<PostOAuthBehaviorResult> HandleRemoteAuthenticationResult()
        {
            try
            {
                var result = await HandleSingInAsync(await InitializeSignInContext());

                if (result.Succeeded)
                {
                    _signInTask = new Task(async () =>
                    {
                        await UserSession.InitializeSessionAsync(result.Principal, result.AuthenticationProperties);
                        await HttpContext.SignInAsync(Scheme.Name, result.Principal, result.AuthenticationProperties);
                    });

                    await HandleOAuthTokensAsync(result, new OAuthTokensContext(OAuthTokens));
                }

                return result;
            }
            catch (Exception ex)
            {
                return PostOAuthBehaviorResult.Failed(ex);
            }
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

            return PostOAuthSingInBehaviorResult.Success(principal, context.AuthenticationProperties);
        }

        protected override async Task HandleSuccessfullBehaviorResult(PostOAuthBehaviorResult result)
        {
            // Clear external cookies
            await HttpContext.SignOutAsync((await HttpContext.GetEveCookieExternalAuthenticationScheme()).Name);

            var returnUrl = OAuthAuthenticateResult.Properties?.Items["returnUrl"];
            if (returnUrl.IsMissing())
            {
                returnUrl = "/";
            }

            HttpContext.Response.Redirect(returnUrl);
        }

        protected override async Task HandleErrors(PostOAuthBehaviorResult result)
        {
            Logger.LogError(result.Error, "Failed to SignIn using authentication scheme: {schemeName}; OAuth Authentication result: {authResult}; OAuth tokens provided: {tokensProvided}",
                Scheme.Name, OAuthAuthenticateResult.Succeeded, OAuthTokens?.Any() == true);

            // clean the tails
            await HttpContext.SignOutAsync((await HttpContext.GetEveCookieExternalAuthenticationScheme()).Name);
            await HttpContext.SignOutAsync((await HttpContext.GetEveCookieAuthenticationScheme()).Name);

            if (OAuthTokens != null && OAuthTokens.Any(x => x.Name == "refresh_token"))
            {
                var request = new RevokeRefreshTokenRequest
                {
                    ClientId = OAuthOptions.ClientId,
                    ClientSecret = OAuthOptions.ClientSecret,
                    RequestUri = new Uri(OAuthOptions.RevokeTokenEndpoint, UriKind.RelativeOrAbsolute),
                    RefreshToken = OAuthTokens.First(x => x.Name == "refresh_token").Value,
                };

                using (var response = await OAuthOptions.Backchannel.RevokeRefreshTokenAsync(request))
                {
                    if (!response.IsSuccessed)
                    {
                        Logger.LogError("Failed to revoke refresh token. Error: {Error}; Error Description: {Description}", response.Error, response.ErrorDescription);
                    }
                }
            }

            if (OAuthOptions.OAuthFailurePath.HasValue)
            {
                HttpContext.Response.Redirect(OAuthOptions.OAuthFailurePath);
            }
            else
            {
                HttpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;

                await HttpContext.Response.WriteAsync($"Failed to SignIn using authentication scheme: {Scheme.Name}");
            }
        }

        protected virtual async Task<SignInBehaviorContext> InitializeSignInContext()
        {
            return SignInBehaviorContext.Initialize(await UserSession.GenerateSessionIdAsync(), new AuthenticationProperties());
        }

        private async Task FinishResponseAsync()
        {
            if (_signInTask != null)
            {
                _signInTask.Start();
                await _signInTask;
            }
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
