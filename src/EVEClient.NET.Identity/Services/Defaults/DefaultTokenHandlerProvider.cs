using System.Diagnostics.CodeAnalysis;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultTokenHandlerProvider : ITokenHandlerProvider
    {
        private readonly EveAuthenticationOptions _options;
        private readonly IAuthenticationHandlerProvider _authenticationHandlerProvider;

        // handler instance cache, need to initialize once per request
        private readonly Dictionary<string, ICollection<object>> _handlerMap = new(StringComparer.Ordinal);

        public DefaultTokenHandlerProvider(IAuthenticationHandlerProvider authenticationHandlerProvider, IOptions<EveAuthenticationOptions> options)
        { 
            _authenticationHandlerProvider = authenticationHandlerProvider;
            _options = options.Value;
        }

        public async Task<IAccessTokenHandler?> GetAccessTokenHandler(HttpContext context, string authenticationScheme)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(authenticationScheme);

            if (_handlerMap.TryGetValue(authenticationScheme, out var values))
            {
                foreach (var value in values)
                {
                    if (value is IAccessTokenHandler accessTokenHandler) return accessTokenHandler;
                }
            }

            var handler = await CreateAccessTokenHandler(context, authenticationScheme);
            if (handler != null)
            {
                var authenticationResult = await AuthenticateAsync(context, authenticationScheme);

                await handler.InitializeAsync(context, authenticationResult.Principal, authenticationResult.Properties);

                if (authenticationResult.Succeeded)
                {
                    if (values != null)
                        values.Add(handler);
                    else
                        _handlerMap[authenticationScheme] = [handler];
                }
            }

            return handler;
        }

        public async Task<IRefreshTokenHandler?> GetRefreshTokenHandler(HttpContext context, string authenticationScheme)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(authenticationScheme);

            if (_handlerMap.TryGetValue(authenticationScheme, out var values))
            {
                foreach (var value in values)
                {
                    if (value is IRefreshTokenHandler refreshTokenHandler) return refreshTokenHandler;
                }
            }

            var handler = await CreateRefreshTokenHandler(context, authenticationScheme);
            if (handler != null)
            {
                var authenticationResult = await AuthenticateAsync(context, authenticationScheme);

                await handler.InitializeAsync(context, authenticationResult.Principal, authenticationResult.Properties);

                if (authenticationResult.Succeeded)
                {
                    if (values != null)
                        values.Add(handler);
                    else
                        _handlerMap[authenticationScheme] = [handler];
                }
            }

            return handler;
        }

        private Task<IAccessTokenHandler?> CreateAccessTokenHandler(HttpContext context, string authenticationScheme)
        {
            ArgumentNullException.ThrowIfNull(authenticationScheme);

            var configuration = _options.TokenHandlerConfigurations.FirstOrDefault(x => x.Scheme == authenticationScheme && x.TokenType == EveConstants.TokenHandler.AccessTokenHandler);
            if (configuration == null)
            {
                return Task.FromResult<IAccessTokenHandler?>(null);
            }

            TryCreateHandler<IAccessTokenHandler>(context.RequestServices, configuration.HandlerType, out var handler);

            if (handler != null)
            {
                handler.Scheme = authenticationScheme;
            }

            return Task.FromResult(handler);
        }

        private Task<IRefreshTokenHandler?> CreateRefreshTokenHandler(HttpContext context, string authenticationScheme)
        {
            ArgumentNullException.ThrowIfNull(authenticationScheme);

            var configuration = _options.TokenHandlerConfigurations.FirstOrDefault(x => x.Scheme == authenticationScheme && x.TokenType == EveConstants.TokenHandler.RefreshTokenHandler);
            if (configuration == null)
            {
                return Task.FromResult<IRefreshTokenHandler?>(null);
            }

            TryCreateHandler<IRefreshTokenHandler>(context.RequestServices, configuration.HandlerType, out var handler);
            
            if (handler != null)
            { 
                handler.Scheme = authenticationScheme;
            }

            return Task.FromResult(handler);
        }

        private async Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string authenticationScheme)
        {
            var authenticationHandler = await _authenticationHandlerProvider.GetHandlerAsync(context, authenticationScheme);

            return authenticationHandler == null
                ? throw new InvalidOperationException($"No authentication handler is configured to authenticate for the scheme: {authenticationScheme}")
                : await authenticationHandler.AuthenticateAsync();
        }

        private static bool TryCreateHandler<THandler>(IServiceProvider serviceProvider, Type handlerType, [NotNullWhen(true)] out THandler? handler)
            where THandler : class
        {
            handler = (serviceProvider.GetService(handlerType) ?? ActivatorUtilities.CreateInstance(serviceProvider, handlerType)) as THandler;

            return handler != null;
        }
    }
}
