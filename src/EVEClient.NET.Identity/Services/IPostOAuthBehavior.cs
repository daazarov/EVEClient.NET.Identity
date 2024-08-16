using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Services
{
    public interface IPostOAuthBehavior
    {
        Task Invoke();

        Task InitializeAsync(AuthenticateResult authenticateResult, HttpContext context);
    }
}
