using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace EVEClient.NET.Identity
{
    public static class EsiAuthenticationExtensions
    {
        /// <summary>
        /// Adds the <see cref="EsiAuthenticationMiddleware"/> or <see cref="EsiEnrichmentContextMiddleware"/> depending on the type of authentication
        /// to the specified <see cref="IApplicationBuilder"/>, which enables authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseEsiAuthentication(this IApplicationBuilder app, EsiAuthenticationMiddlewareOptions? options = null)
        {
            ArgumentNullException.ThrowIfNull(app);

            app.UseWhen(
                predicate: context => context.Request.Path == EveConstants.PostOAuthCallbackPath,
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

                        var authResult = await handler.AuthenticateAsync();

                        await behavior.InitializeAsync(authResult, context);
                        await behavior.Invoke();
                    });
                });

            if (options is null)
            {
                options = new EsiAuthenticationMiddlewareOptions();
            }

            options.AuthenticationMiddleware(app);

            app.UseMiddleware<EsiAuthenticationMiddleware>();

            return app;
        }
    }
}
