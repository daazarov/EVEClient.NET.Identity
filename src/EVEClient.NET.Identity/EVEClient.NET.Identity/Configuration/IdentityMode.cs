namespace EVEClient.NET.Identity.Configuration
{
    public enum IdentityMode
    {
        /// <summary>
        /// Indicates that EVE Identity is prioritized. If the user is not authenticated via EVEAuthenticationScheme, HttpContext.User.Identity will return null anyway.
        /// </summary>
        PrimaryIdentity,

        /// <summary>
        /// Indicates that the EVE Identity is not prioritized.
        /// If the user is authenticated via EVEAuthenticationScheme but does not have any other valid authentication, HttpContext.User.Identity will return null
        /// </summary>
        /// <remarks>
        /// You can still get the user's EVE authentication context and all related things, this parameter is only responsible for authenticating the user in the current request.
        /// You can also get EVE Identity through Linq (e.g. <code>principal.Identities.FirstOrDefault(x => x.AuthenticationType == EveConstants.AuthenticationType)</code> for example.)
        /// </remarks>
        SecondaryIdentity,

        /// <summary>
        /// 
        /// </summary>
        MixedIdentity
    }
}
