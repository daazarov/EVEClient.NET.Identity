using Microsoft.AspNetCore.Authentication;

using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Services
{
    public class SignInBehaviorContext
    {
        /// <summary>
        /// Gets the current EVE session ID.
        /// </summary>
        public string SessionId { get; }

        /// <summary>
        /// Gets the created authentication properties.
        /// </summary>
        public AuthenticationProperties AuthenticationProperties { get; }

        public SignInBehaviorContext(SignInBehaviorContext copyFrom)
        {
            ArgumentNullException.ThrowIfNull(copyFrom);

            SessionId = copyFrom.SessionId;
            AuthenticationProperties = copyFrom.AuthenticationProperties;
        }

        private SignInBehaviorContext(string sessionId, AuthenticationProperties properties)
        {
            ArgumentNullException.ThrowIfNull(sessionId);
            ArgumentNullException.ThrowIfNull(properties);

            SessionId = sessionId;
            AuthenticationProperties = properties;
        }

        public static SignInBehaviorContext Initialize(string sessionId, AuthenticationProperties properties)
        {
            if (properties.GetUserSessionId().IsMissing())
            {
                properties.StoreUserSessionId(sessionId);
            }
            
            return new SignInBehaviorContext(sessionId, properties);
        }
    }
}
