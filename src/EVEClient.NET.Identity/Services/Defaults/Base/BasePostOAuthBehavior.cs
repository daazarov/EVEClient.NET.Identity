﻿using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Defaults;
using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Services
{
    public abstract class BasePostOAuthBehavior : IPostOAuthBehavior
    {
        private Exception? _initFailure;
        private bool _initSucceeded;

        /// <summary>
        /// Gets the <see cref="ILogger"/>
        /// </summary>
        protected ILogger<BasePostOAuthBehavior> Logger { get; }

        /// <summary>
        /// If oauth ticket was produced, authenticate was successful.
        /// </summary>
        public bool OAuthAuthenticationSucceeded => OAuthAuthenticateResult.Succeeded;

        /// <summary>
        /// Gets or sets the <see cref="Microsoft.AspNetCore.Http.HttpContext"/>.
        /// </summary>
        protected HttpContext HttpContext { get; private set; } = default!;

        /// <summary>
        /// Gets or sets the <see cref="AuthenticateResult"/> after passing the external authentication.
        /// </summary>
        protected AuthenticateResult OAuthAuthenticateResult { get; private set; } = default!;

        /// <summary>
        /// Gets the <see cref="IOptionsMonitor{EVEAuthenticationOAuthOptions}"/> to detect changes to options.
        /// </summary>
        protected IOptionsMonitor<EveAuthenticationOAuthOptions> OptionsMonitor { get; }

        /// <summary>
        /// Gets or sets the options associated with EVE OAuth authentication handler.
        /// </summary>
        protected EveAuthenticationOAuthOptions OAuthOptions { get; private set; } = default!;

        /// <summary>
        /// Gets the issuer that should be used when any claims are issued.
        /// </summary>
        /// <value>
        /// The <c>ClaimsIssuer</c> configured in <see cref="EveAuthenticationOAuthOptions"/>, if configured.
        /// </value>
        protected virtual string? ClaimsIssuer => OAuthOptions.ClaimsIssuer;

        /// <summary>
        /// Get the tokens that have been provided by an EVE SSO.
        /// </summary>
        protected IReadOnlyCollection<AuthenticationToken> OAuthTokens { get; private set; } = default!;

        /// <summary>
        /// Gets the claims-principal with authenticated user external identities.
        /// </summary>
        protected ClaimsPrincipal OAuthPrincipal { get; private set; } = default!;

        /// <summary>
        /// Gets the normalized subject (an EVE Character ID) from extarnal claims.
        /// </summary>
        protected string SubjectId { get; private set; } = default!;

        public BasePostOAuthBehavior(ILogger<BasePostOAuthBehavior> logger, IOptionsMonitor<EveAuthenticationOAuthOptions> options)
        {
            ArgumentNullException.ThrowIfNull(logger);
            ArgumentNullException.ThrowIfNull(options);

            Logger = logger;
            OptionsMonitor = options;
        }

        public virtual Task InitializeAsync(AuthenticateResult externalAuthenticateResult, HttpContext context)
        {
            ArgumentNullException.ThrowIfNull(externalAuthenticateResult);
            ArgumentNullException.ThrowIfNull(context);

            OAuthAuthenticateResult = externalAuthenticateResult;
            HttpContext = context;
            OAuthOptions = OptionsMonitor.Get(EveAuthenticationCookieDefaults.OAuth.DefaultOAuthSchemeName);

            if (OAuthAuthenticationSucceeded)
            {
                OAuthPrincipal = OAuthAuthenticateResult.Principal!;
                SubjectId = OAuthPrincipal.Claims.First(x => x.Type == EveClaims.Issuers.Subject).Value.EnshureEveSubjectNormalized();

                var ouathTokens = OAuthAuthenticateResult.Properties?.GetTokens();
                if (ouathTokens != null && ouathTokens.Any())
                {
                    OAuthTokens = ouathTokens.ToList();
                    _initSucceeded = true;
                }
                else
                {
                    _initSucceeded = false;
                    _initFailure = new InvalidOperationException("No tokens were found in the AuthenticateResult. Did you forget to enable SaveTokens = true in the OAuthOptions?");
                }
            }
            else
            {
                _initSucceeded = false;
                _initFailure = OAuthAuthenticateResult.Failure;
            }

            return Task.CompletedTask;
        }

        public async Task Invoke()
        {
            if (_initSucceeded)
            {
                var result = await HandleRemoteAuthenticationResult();
                if (result.Succeeded)
                {
                    await HandleSuccessfullBehaviorResult(result);
                }
                else
                {
                    await HandleErrors(result);
                }
            }
            else
            {
                await HandleErrors(PostOAuthBehaviorResult.Failed(_initFailure ?? new Exception("Unhandled exception during initialization.")));
            }
        }

        /// <summary>
        /// Allows derived types to handle remote authentication results.
        /// </summary>
        /// <returns>The <see cref="Task{TResult}"/> that will contain the <see cref="PostOAuthBehaviorResult"/> when completed..</returns>
        protected abstract Task<PostOAuthBehaviorResult> HandleRemoteAuthenticationResult();

        /// <summary>
        /// Called after a successful result of a <see cref="HandleRemoteAuthenticationResult()"/> call.
        /// </summary>
        /// <param name="result">The <see cref="PostOAuthBehaviorResult"/>.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        protected abstract Task HandleSuccessfullBehaviorResult(PostOAuthBehaviorResult result);

        /// <summary>
        /// Called after an unsuccessful result of a <see cref="HandleRemoteAuthenticationResult()"/> call.
        /// </summary>
        /// <param name="result">The <see cref="PostOAuthBehaviorResult"/>.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        protected abstract Task HandleErrors(PostOAuthBehaviorResult result);
    }
}
