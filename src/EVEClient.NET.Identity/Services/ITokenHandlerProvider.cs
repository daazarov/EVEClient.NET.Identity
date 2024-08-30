using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Services
{
    public interface ITokenHandlerProvider
    {
        Task<IAccessTokenHandler?> GetAccessTokenHandler(HttpContext context, string authenticationScheme, bool initialize = true);

        Task<IRefreshTokenHandler?> GetRefreshTokenHandler(HttpContext context, string authenticationScheme, bool initialize = true);
    }
}
