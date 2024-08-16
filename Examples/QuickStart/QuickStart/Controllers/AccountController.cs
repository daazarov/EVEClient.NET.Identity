using EVEClient.NET.Identity.Extensions;
using Microsoft.AspNetCore.Mvc;

namespace QuickStart.Controllers
{
    public class AccountController : Controller
    {
        public async Task<IActionResult> Login(string returnUrl)
        {
            return await this.EveChallengeAsync(returnUrl);
        }

        public async Task<IActionResult> Logout(string returnUrl)
        {
            // removes auth cookie
            // clean tokens store
            // revokes refresh token on the ESI SSO side
            await HttpContext.EveSingOutAsync();

            return Redirect(returnUrl);
        }
    }
}
