using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Defaults;
using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Services
{
    public abstract class BaseEveTokenHandler<TResult> : BaseTokenHandler<TResult> where TResult : class
    {
        /// <summary>
        /// Gets the <see cref="EveAuthenticationOAuthOptions"/>.
        /// </summary>
        protected EveAuthenticationOAuthOptions Options { get; }

        /// <summary>
        /// Gets the <see cref="EveOAuthEvents"/>.
        /// </summary>
        protected EveOAuthEvents Events => (EveOAuthEvents)Options.Events;

        /// <summary>
        /// Gets the <see cref="HttpClient"/> instance used to communicate with the remote authentication provider.
        /// </summary>
        protected HttpClient Backchannel => Options.Backchannel;

        /// <summary>
        /// Gets the subject id (aka EVE character ID).
        /// </summary>
        protected string? SubjectId { get; private set; }

        /// <summary>
        /// Gets the EVE session id.
        /// </summary>
        protected string? SessionId { get; private set; }

        [MemberNotNullWhen(true, nameof(SubjectId), nameof(SessionId))]
        public override bool IsAuthenticated => base.IsAuthenticated && Principal.Identity.IsEveIdentity();

        public BaseEveTokenHandler(ILogger logger, IOptionsMonitor<EveAuthenticationOAuthOptions> options)
            : base(logger)
        {
            Options = options.Get(EveAuthenticationCookieDefaults.OAuth.DefaultOAuthSchemeName);
        }

        public override async Task InitializeAsync(HttpContext context, ClaimsPrincipal? principal, AuthenticationProperties? properties)
        {
            await base.InitializeAsync(context, principal, properties);

            if (IsAuthenticated)
            {
                SubjectId = Principal.GetEveSubject();
                SessionId = AuthenticationProperties.GetUserSessionId() ?? 
                    throw new InvalidOperationException("Missing EVE session identifier in the AuthenticationProperties.");
            }
        }
    }
}
