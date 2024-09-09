using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Stores;
using EVEClient.NET.Identity.Services;
using EVEClient.NET.Identity.Configuration;

namespace EVEClient.NET.Identity
{
    public static class EsiAuthenticationExtensions
    {
        private static bool _validated = false;

        /// <summary>
        /// Adds the <see cref="EsiAuthenticationMiddleware"/> or <see cref="EsiEnrichmentContextMiddleware"/> depending on the type of authentication
        /// to the specified <see cref="IApplicationBuilder"/>, which enables authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        /// <remarks>Containce app.UseAuthentication() method call.</remarks>
        public static IApplicationBuilder UseEsiAuthentication(this IApplicationBuilder app)
        {
            ArgumentNullException.ThrowIfNull(app);

            app.Validate();

            app.UseWhen(
                predicate: context => context.Request.Path == EveConstants.OAuth.PostOAuthCallbackPath,
                branch =>
                {
                    branch.Use(next => async context =>
                    {
                        var behavior = context.RequestServices.GetRequiredService<IPostOAuthBehavior>();
                        var handlers = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();

                        var scheme = await context.GetEveCookieExternalAuthenticationScheme();
                        var handler = await handlers.GetHandlerAsync(context, scheme.Name);

                        if (handler == null)
                        {
                            throw new InvalidOperationException($"No authentication handler is configured to authenticate for the EVE scheme: {scheme.Name}");
                        }

                        var authenticateResult = await handler.AuthenticateAsync();

                        await behavior.InitializeAsync(authenticateResult, context);
                        await behavior.Invoke();
                    });
                });

            // To keep the the OAuthHandler running and Mixed/Secondary identity mode authentication.
            app.UseAuthentication();

            app.UseMiddleware<EsiAuthenticationMiddleware>();

            return app;
        }

        private static IApplicationBuilder Validate(this IApplicationBuilder app)
        {
            if (_validated)
            {
                return app;
            }
            
            var scopeFactory = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>();

            using (var scope = scopeFactory.CreateScope())
            {
                var serviceProvider = scope.ServiceProvider;

                var logger = app.ApplicationServices.GetRequiredService<ILoggerFactory>().CreateLogger("EVEClient.NET.Identity.Startup");
                var options = app.ApplicationServices.GetRequiredService<IOptions<EveAuthenticationOptions>>().Value;
                var userDataStore = serviceProvider.GetRequiredService<IUserDataStore>();

                if (!options.UseCookieStorage && userDataStore.GetType().FullName == typeof(DefaultInMemoryUserDataStore).FullName)
                {
                    logger.LogWarning("You are using the in-memory version of the user data store. " +
                        "This will store refresh and access tokens in memory only. " +
                        "You may lose data when you restart the application. We recommend that you use this storage type only for the development. " +
                        "For production use, implement a more robust solution using .AddUserDataStore<YourStoreType>().");
                }
            }

            return app;
        }
    }
}
