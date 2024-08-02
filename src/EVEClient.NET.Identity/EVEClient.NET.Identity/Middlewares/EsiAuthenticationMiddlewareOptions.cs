using Microsoft.AspNetCore.Builder;

namespace EVEClient.NET.Identity
{
    public class EsiAuthenticationMiddlewareOptions
    {
        public Action<IApplicationBuilder> AuthenticationMiddleware { get; set; } = (app) => app.UseAuthentication();
    }
}
