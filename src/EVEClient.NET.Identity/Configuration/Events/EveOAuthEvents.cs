using Microsoft.AspNetCore.Authentication.OAuth;

namespace EVEClient.NET.Identity.Configuration
{
    public class EveOAuthEvents : OAuthEvents
    {
        /// <summary>
        /// Invoked when failed to retrieve access token from internal storage.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task FailRenewAccessToken(EveRenewAccessTokenFailureContext context) => OnFailedRenewAccessToken(context);

        /// <summary>
        /// Invoked after success refreshing token from external OAuth provider.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task SuccessRenewAccessToken(EveRenewAccessTokenSuccessContext context) => OnSuccessRenewAccessToken(context);

        /// <summary>
        /// Gets or sets the function that is invoked when the FailRenewAccessToken method is invoked.
        /// </summary>
        public Func<EveRenewAccessTokenFailureContext, Task> OnFailedRenewAccessToken { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Gets or adds the function that is invoked when the SuccessRenewAccessToken method is invoked.
        /// </summary>
        public Func<EveRenewAccessTokenSuccessContext, Task> OnSuccessRenewAccessToken { get; set; } = context => Task.CompletedTask;
    }
}
