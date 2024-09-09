using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace EVEClient.NET.Identity.Services
{
    public abstract class BaseTokenHandler<TResult> : ITokenHandler<TResult> where TResult : class
    {
        /// <summary>
        /// Gets the <see cref="ILogger"/>.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets the <see cref="Microsoft.AspNetCore.Http.HttpContext"/>.
        /// </summary>
        protected HttpContext HttpContext { get; private set; } = default!;

        /// <summary>
        /// Gets the authentication scheme name.
        /// </summary>
        protected string Scheme { get; private set; } = default!;

        string ITokenHandler<TResult>.Scheme
        {
            get => Scheme;
            set => Scheme = value;
        }

        /// <summary>
        /// Gets the <see cref="ClaimsPrincipal"/>.
        /// </summary>
        protected ClaimsPrincipal? Principal { get; private set; } = default!;

        /// <summary>
        /// Gets the <see cref="Microsoft.AspNetCore.Authentication.AuthenticationProperties"/>.
        /// </summary>
        protected AuthenticationProperties? AuthenticationProperties { get; private set; } = default!;

        /// <summary>
        /// Gets a value indicating whether the user context can be considered valid after initialization.
        /// </summary>
        [MemberNotNullWhen(true, nameof(Principal), nameof(AuthenticationProperties))]
        public virtual bool IsAuthenticated => AuthenticationProperties != null && Principal?.Identity?.IsAuthenticated == true;

        public BaseTokenHandler(ILogger logger)
        { 
            Logger = logger;
        }

        public virtual Task InitializeAsync(HttpContext context, ClaimsPrincipal? principal, AuthenticationProperties? properties)
        {
            ArgumentNullException.ThrowIfNull(context);

            HttpContext = context;
            Principal = principal;
            AuthenticationProperties = properties;

            return Task.CompletedTask;
        }

        public abstract Task<TResult> RequestTokenAsync();
    }
}
