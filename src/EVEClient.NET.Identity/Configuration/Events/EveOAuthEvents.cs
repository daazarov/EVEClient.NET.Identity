using Microsoft.AspNetCore.Authentication.OAuth;

namespace EVEClient.NET.Identity.Configuration
{
    public class EveOAuthEvents : OAuthEvents
    {
        /// <summary>
        /// Gets or sets the function that is invoked when the FailRenewAccessToken method is invoked.
        /// </summary>
        public Func<EveRenewAccessTokenFailureContext, Task> OnFailedRenewAccessToken { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when failed to retrieve access token from internal storage.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task FailRenewAccessToken(EveRenewAccessTokenFailureContext context) => OnFailedRenewAccessToken(context);
    }
}
