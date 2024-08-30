using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Defaults;

namespace EVEClient.NET.Identity.Services
{
    public abstract class DefaultTokenHandler<TResult> : ITokenHandler<TResult> where TResult : class
    {
        protected ILogger Logger { get; }

        protected HttpContext HttpContext { get; private set; } = default!;

        protected ClaimsPrincipal? Principal { get; private set; } = default!;

        protected AuthenticationProperties? AuthenticationProperties { get; private set; } = default!;

        protected EveAuthenticationOAuthOptions Options { get; private set; }

        protected EveOAuthEvents Events => (EveOAuthEvents)Options.Events;

        [MemberNotNullWhen(true, nameof(Principal), nameof(AuthenticationProperties))]
        public virtual bool Authenticated => AuthenticationProperties != null && Principal != null && Principal.Identity?.IsAuthenticated == true;

        /// <summary>
        /// Gets the <see cref="HttpClient"/> instance used to communicate with the remote authentication provider.
        /// </summary>
        protected HttpClient Backchannel => Options.Backchannel;

        public DefaultTokenHandler(ILogger logger, IOptionsMonitor<EveAuthenticationOAuthOptions> options)
        { 
            Logger = logger;

            Options = options.Get(EveAuthenticationCookieDefaults.OAuth.DefaultOAuthAuthenticationSchemeName);
        }

        public abstract Task<TResult> HandleTokenRequest();

        public Task InitializeAsync(HttpContext context, ClaimsPrincipal? principal, AuthenticationProperties? properties)
        {
            ArgumentNullException.ThrowIfNull(context);

            HttpContext = context;
            Principal = principal;
            AuthenticationProperties = properties;

            return Task.CompletedTask;
        }
    }
}
