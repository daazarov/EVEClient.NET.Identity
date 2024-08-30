using Microsoft.AspNetCore.Authentication;

namespace EVEClient.NET.Identity.Extensions
{
    public static class AuthenticationPropertiesExtensions
    {
        private const string EveKeyPrefix = ".eve.";
        private const string EveUserSessionKey = "session";

        /// <summary>
        /// Returns the value of a session identifier.
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> properties.</param>
        /// <returns>The session id value.</returns>
        public static string? GetUserSessionId(this AuthenticationProperties properties)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (properties.Items.TryGetValue(EveKeyPrefix + EveUserSessionKey, out var value) && !string.IsNullOrEmpty(value))
            {
                return value;
            }

            return null;
        }

        /// <summary>
        /// Store the value of a session id.
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> properties.</param>
        /// <param name="sessionId">The session identifier.</param>
        public static void StoreUserSessionId(this AuthenticationProperties properties, string sessionId)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (sessionId.IsMissing())
            {
                throw new ArgumentException("SessionId cannot be null or empty.", nameof(sessionId));
            }

            properties.Items[EveKeyPrefix + EveUserSessionKey] = sessionId;
        }

        /// <summary>
        /// Checks that all necessary properties are present in the <see cref="AuthenticationProperties"/> for correct work of EVE authentication.
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> properties.</param>
        public static bool ValidateForEveOnline(this AuthenticationProperties properties)
        {
            return properties.GetUserSessionId().IsPresent();
        }
    }
}
