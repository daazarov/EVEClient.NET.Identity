using EVEClient.NET.Extensions;
using EVEClient.NET.Identity.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultUserSession : IUserSession
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IAuthenticationHandlerProvider _authenticationHandlerProvider;

        /// <summary>
        /// Gets the current authentication principal.
        /// </summary>
        protected ClaimsPrincipal? Principal;

        /// <summary>
        /// Gets the current authentication properties.
        /// </summary>
        protected AuthenticationProperties? AuthenticationProperties;

        public DefaultUserSession(IHttpContextAccessor contextAccessor, IAuthenticationHandlerProvider authenticationHandlerProvider)
        {
            ArgumentNullException.ThrowIfNull(contextAccessor);
            ArgumentNullException.ThrowIfNull(authenticationHandlerProvider);

            _contextAccessor = contextAccessor;
            _authenticationHandlerProvider = authenticationHandlerProvider;
        }

        public Task InitializeSessionAsync(ClaimsPrincipal principal, AuthenticationProperties properties)
        {
            ArgumentNullException.ThrowIfNull(principal);
            ArgumentNullException.ThrowIfNull(properties);

            if (properties.GetUserSessionId().IsMissing())
            {
                throw new InvalidOperationException("Missing session identifier in the authentication properties.");
            }

            Principal = principal;
            AuthenticationProperties = properties;

            return Task.CompletedTask;
        }

        public async Task<string?> GetCurrentSessionIdAsync()
        {
            if (Principal == null || AuthenticationProperties == null)
            {
                await AuthenticateAsync();
            }

            return AuthenticationProperties?.GetUserSessionId();
        }

        public async Task<string?> GetAccessTokenReferenceKeyAsync()
        {
            if (Principal == null || AuthenticationProperties == null)
            {
                await AuthenticateAsync();
            }

            return AuthenticationProperties?.GetEveAccessTokenReferenceKey();
        }

        public async Task<string?> GetRefreshTokenReferenceKeyAsync()
        {
            if (Principal == null || AuthenticationProperties == null)
            {
                await AuthenticateAsync();
            }

            return AuthenticationProperties?.GetEveRefreshTokenReferenceKey();
        }

        public async Task<string?> GetCurrentSubjectIdAsync()
        {
            return (await GetCurrentUserAsync())?.GetEveSubject();
        }

        public Task<string> GenerateSessionIdAsync()
        {
            return Task.FromResult(Guid.NewGuid().ToString().MD5());
        }

        public async Task<ClaimsPrincipal?> GetCurrentUserAsync()
        {
            await AuthenticateAsync();

            return Principal;
        }

        private async Task AuthenticateAsync()
        {
            if (Principal == null || AuthenticationProperties == null)
            {
                var context = _contextAccessor.HttpContext;
                if (context == null)
                {
                    throw new ArgumentException("HttpContext cannot be null.", nameof(context));
                }

                var scheme = await context.GetEveCookieAuthenticationSchemeName();
                var handler = await _authenticationHandlerProvider.GetHandlerAsync(context, scheme);

                if (handler == null)
                {
                    throw new InvalidOperationException($"No authentication handler is configured to authenticate for the EVE scheme: {scheme}");
                }

                var result = await handler.AuthenticateAsync();

                if (result.Succeeded)
                {
                    Principal = result.Principal;
                    AuthenticationProperties = result.Properties;
                }
            }
        }
    }
}
