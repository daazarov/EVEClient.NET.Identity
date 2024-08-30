using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.DependencyInjection;
using EVEClient.NET.Identity.Services;
using EVEClient.NET.Identity.Stores;
using EVEClient.NET.Identity.Validators;
using EVEClient.NET.Identity.Defaults;
using EVEClient.NET.Identity.OAuth;

namespace EVEClient.NET.Identity.Extensions.DependencyInjection
{
    public static class EsiClientConfigurationBuilderExtensions
    {
        /// <summary>
        /// Registers services required for successfull authentication in EVE Online SSO.
        /// </summary>
        /// <param name="builder">The <see cref="IEsiClientConfigurationBuilder"/> builder.</param>
        /// <param name="options"></param>
        public static IEsiClientConfigurationBuilder AddAuthentication(this IEsiClientConfigurationBuilder builder, Action<EveAuthenticationOptions> options)
        {
            ArgumentNullException.ThrowIfNull(options);

            var configured = new EveAuthenticationOptions();

            options(configured);

            builder.Services.Configure(options);
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<EveAuthenticationOptions>, ConfigurePrimaryIdentitySelector>());

            builder.AddAccessTokenProvider<DefaultAccessTokenProvider>();
            builder.AddScopeValidator<DefaultScopeAccessValidator>();
            builder.AddAccessTokenHandler<DefaultEveAccessTokenHandler>(configured.CookieAuthenticationScheme);
            builder.AddRefreshTokenHandler<DefaultEveRefreshTokenHandler>(configured.CookieAuthenticationScheme);

            return builder.AddAuthentication(configured, oauthOptions =>
            {
                oauthOptions.Events = configured.OAuthEvents;
                oauthOptions.ClientId = configured.ClientId;
                oauthOptions.ClientSecret = configured.ClientSecret;
                oauthOptions.Scope.AddRange(configured.Scopes);
                oauthOptions.SignInScheme = configured.CookieExternalAuthenticationScheme;
                oauthOptions.CallbackPath = configured.CallbackPath;
                oauthOptions.Server = builder.Configuration.Server;
                oauthOptions.SaveTokens = true;
            });
        }

        /// <summary>
        /// Adds custom post auth behavior.
        /// </summary>
        /// <typeparam name="T">The <see cref="IPostOAuthBehavior"/> implementation.</typeparam>
        /// <param name="builder">The <see cref="IEsiClientConfigurationBuilder"/> builder.</param>
        public static IEsiClientConfigurationBuilder AddPostOAuthBehavior<T>(this IEsiClientConfigurationBuilder builder)
            where T : class, IPostOAuthBehavior
        {
            builder.Services.AddScopedWithReplace<IPostOAuthBehavior, T>();

            return builder;
        }

        /// <summary>
        /// Adds custom user data storage.
        /// </summary>
        /// <typeparam name="T">The <see cref="IUserDataStore"/> implementation.</typeparam>
        /// <param name="builder">The <see cref="IEsiClientConfigurationBuilder"/> builder.</param>
        public static IEsiClientConfigurationBuilder AddUserDataStore<T>(this IEsiClientConfigurationBuilder builder)
            where T : class, IUserDataStore
        {
            builder.Services.AddScopedWithReplace<IUserDataStore, T>();

            return builder;
        }

        /// <summary>
        /// Adds custom access token storage.
        /// </summary>
        /// <typeparam name="T">The <see cref="IAccessTokenStore"/> implementation.</typeparam>
        /// <param name="builder">The <see cref="IEsiClientConfigurationBuilder"/> builder.</param>
        public static IEsiClientConfigurationBuilder AddAccessTokenStore<T>(this IEsiClientConfigurationBuilder builder)
            where T : class, IAccessTokenStore
        {
            builder.Services.AddScopedWithReplace<IAccessTokenStore, T>();

            return builder;
        }

        /// <summary>
        /// Adds custom refresh token storage.
        /// </summary>
        /// <typeparam name="T">The <see cref="IRefreshTokenStore"/> implementation.</typeparam>
        /// <param name="builder">The <see cref="IEsiClientConfigurationBuilder"/> builder.</param>
        public static IEsiClientConfigurationBuilder AddRefreshTokenStore<T>(this IEsiClientConfigurationBuilder builder)
            where T : class, IRefreshTokenStore
        {
            builder.Services.AddScopedWithReplace<IRefreshTokenStore, T>();

            return builder;
        }

        /// <summary>
        /// Adds custom eve user accessor.
        /// </summary>
        /// <typeparam name="T">The <see cref="IEveUserAccessor{TUser}"/> implementation.</typeparam>
        /// <typeparam name="TUser">The <see cref="IEveUser"/> implementation.</typeparam>
        /// <param name="builder">The <see cref="IEsiClientConfigurationBuilder"/> builder.</param>
        public static IEsiClientConfigurationBuilder AddEveUserAccessor<T, TUser>(this IEsiClientConfigurationBuilder builder)
            where T : class, IEveUserAccessor<TUser>
            where TUser : class, IEveUser
        {
            builder.Services.TryAddScoped<IEveUserAccessor<TUser>, T>();

            return builder;
        }

        /// <summary>
        /// Adds additional user claim transformator.
        /// </summary>
        /// <typeparam name="T">The <see cref="IUserClaimsTransformator"/> implementation.</typeparam>
        /// <param name="builder">The <see cref="IEsiClientConfigurationBuilder"/> builder.</param>
        /// <remarks>The claim transformators will be executed in the order in which they are added to service collection.</remarks>
        public static IEsiClientConfigurationBuilder AddUserClaimTransformator<T>(this IEsiClientConfigurationBuilder builder)
            where T : class, IUserClaimsTransformator
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Scoped(typeof(IUserClaimsTransformator), typeof(T)));

            return builder;
        }

        /// <summary>
        /// Registers required services required for successfull authentication in EVE Online SSO.
        /// </summary>
        /// <param name="builder">The <see cref="IEsiClientConfigurationBuilder"/> builder.</param>
        public static IEsiClientConfigurationBuilder AddRequiredIdentityServices(this IEsiClientConfigurationBuilder builder)
        {
            builder.Services.AddHttpContextAccessor();

            builder.Services.TryAddScoped<ITokenService, DefaultTokenService>();
            builder.Services.TryAddScoped<IUserSession, DefaultUserSession>();
            builder.Services.TryAddScoped<IUserDataStore, DefaultInMemoryUserDataStore>();
            builder.Services.TryAddScoped<IAccessTokenStore, DefaultAccessTokenStore>();
            builder.Services.TryAddScoped<IRefreshTokenStore, DefaultRefreshTokenStore>();
            builder.Services.TryAddScoped<IReceivedAccessTokenValidator, DefaultReceivedAccessTokenValidator>();
            builder.Services.TryAddScoped<IRequiredClaimsValidator, DefaultRequiredClaimsValidator>();
            builder.Services.TryAddScoped<IEveUserAccessor<EveOnlineUser>, EveUserAccessor>();
            builder.Services.TryAddScoped<IPostOAuthBehavior, DefaultSignInPostOAuthBehavior>();
            builder.Services.TryAddScoped<ITokenHandlerProvider, DefaultTokenHandlerProvider>();

            builder.Services.TryAddEnumerable(ServiceDescriptor.Scoped(typeof(IUserClaimsTransformator), typeof(SubjectClaimNormalizator)));
            builder.Services.TryAddEnumerable(ServiceDescriptor.Scoped(typeof(IUserClaimsTransformator), typeof(EveOnlineUserClaimsEnricher)));

            return builder;
        }

        /// <summary>
        /// Registers access token handler for the specific authentication scheme name.
        /// </summary>
        /// <typeparam name="THandler">The <see cref="IAccessTokenHandler"/> implementation.</typeparam>
        /// <param name="builder">The <see cref="IEsiClientConfigurationBuilder"/> builder.</param>
        /// <param name="authenticationScheme">The authentication scheme name.</param>
        public static IEsiClientConfigurationBuilder AddAccessTokenHandler<THandler>(this IEsiClientConfigurationBuilder builder, string authenticationScheme)
            where THandler : class, IAccessTokenHandler
        {
            if (string.IsNullOrEmpty(authenticationScheme))
            {
                throw new ArgumentNullException(nameof(authenticationScheme));
            }

            builder.AddTokenHandler<THandler, AccessTokenResult>(configure =>
            {
                configure.HandlerType = typeof(THandler);
                configure.Scheme = authenticationScheme;
                configure.TokenType = EveConstants.TokenHandler.AccessTokenHandler;
            });

            return builder;
        }

        /// <summary>
        /// Registers refresh token handler for the specific authentication scheme name.
        /// </summary>
        /// <typeparam name="THandler">The <see cref="IRefreshTokenHandler"/> implementation.</typeparam>
        /// <param name="builder">The <see cref="IEsiClientConfigurationBuilder"/> builder.</param>
        /// <param name="authenticationScheme">The authentication scheme name.</param>
        public static IEsiClientConfigurationBuilder AddRefreshTokenHandler<THandler>(this IEsiClientConfigurationBuilder builder, string authenticationScheme)
            where THandler : class, IRefreshTokenHandler
        {
            if (string.IsNullOrEmpty(authenticationScheme))
            {
                throw new ArgumentNullException(nameof(authenticationScheme));
            }

            builder.AddTokenHandler<THandler, RefreshTokenResult>(configure =>
            {
                configure.HandlerType = typeof(THandler);
                configure.Scheme = authenticationScheme;
                configure.TokenType = EveConstants.TokenHandler.RefreshTokenHandler;
            });

            return builder;
        }

        public static IEsiClientConfigurationBuilder AddTokenHandler<THandler, TResult>(this IEsiClientConfigurationBuilder builder, Action<TokenHandlerConfiguration> configure)
            where THandler : class, ITokenHandler<TResult>
            where TResult : class
        {
            ArgumentNullException.ThrowIfNull(configure);

            builder.Services.Configure<EveAuthenticationOptions>(o =>
            {
                o.AddTokenHandler(configure);
            });

            builder.Services.TryAddTransient<THandler>();

            return builder;
        }

        private static IEsiClientConfigurationBuilder AddAuthentication(this IEsiClientConfigurationBuilder builder, EveAuthenticationOptions options, Action<EveAuthenticationOAuthOptions> oauthOptions)
        {
            var authenticationBuilder = options.IdentityMode == IdentityMode.PrimaryIdentity
                ? builder.Services.AddAuthentication(options.CookieAuthenticationScheme)
                : builder.Services.AddAuthentication();

            authenticationBuilder
                .AddApplicationCookieSchemes(options)
                .AddOAuthCookieScheme(oauthOptions);

            builder.AddRequiredIdentityServices();

            return builder;
        }

        private static AuthenticationBuilder AddApplicationCookieSchemes(this AuthenticationBuilder builder, EveAuthenticationOptions options)
        {
            builder.AddCookie(options.CookieAuthenticationScheme);
            builder.AddCookie(options.CookieExternalAuthenticationScheme);

            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<CookieAuthenticationOptions>, ConfigureEveCookieOptions>());

            return builder;
        }

        private static AuthenticationBuilder AddOAuthCookieScheme(this AuthenticationBuilder builder, Action<EveAuthenticationOAuthOptions> oauthOptions)
        {
            builder.AddOAuth<EveAuthenticationOAuthOptions, EveOAuthHandler>(EveAuthenticationCookieDefaults.OAuth.DefaultOAuthAuthenticationSchemeName, EveAuthenticationCookieDefaults.OAuth.DefaultOAuthAuthenticationSchemeDisplayName, oauthOptions);

            return builder;
        }
    }
}
