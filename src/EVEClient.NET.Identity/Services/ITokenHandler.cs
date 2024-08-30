using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Services
{
    public interface ITokenHandler<TResult> where TResult : class
    {
        Task<TResult> HandleTokenRequest();

        Task InitializeAsync(HttpContext context, ClaimsPrincipal? principal, AuthenticationProperties? properties);
    }
}
