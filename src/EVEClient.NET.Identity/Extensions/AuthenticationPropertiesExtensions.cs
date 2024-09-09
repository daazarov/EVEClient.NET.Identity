using Microsoft.AspNetCore.Authentication;

namespace EVEClient.NET.Identity.Extensions
{
    public static class AuthenticationPropertiesExtensions
    {
        private const string EveKeyPrefix = ".eve.";
        private const string EveUserSessionKey = "session";
        private const string EveUserTokenKeyPrefix = "key.token.";
        private const string EveUserAccessTokenKey = EveUserTokenKeyPrefix + "access";
        private const string EveUserRefreshTokenKey = EveUserTokenKeyPrefix + "refresh";

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
        /// Returns the value of a access token storage key.
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> properties.</param>
        /// <returns>The storage key.</returns>
        public static string? GetAccessTokenStorageKey(this AuthenticationProperties properties)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (properties.Items.TryGetValue(EveKeyPrefix + EveUserAccessTokenKey, out var value) && !string.IsNullOrEmpty(value))
            {
                return value;
            }

            return null;
        }

        /// <summary>
        /// Store the value of a access token storage key.
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> properties.</param>
        /// <param name="key">The storage key.</param>
        public static void StoreAccessTokenStorageKey(this AuthenticationProperties properties, string key)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (key.IsMissing())
            {
                throw new ArgumentException("Storage key cannot be null or empty.", nameof(key));
            }

            properties.Items[EveKeyPrefix + EveUserAccessTokenKey] = key;
        }

        /// <summary>
        /// Returns the value of a refresh token storage key.
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> properties.</param>
        /// <returns>The storage key.</returns>
        public static string? GetRefreshTokenStorageKey(this AuthenticationProperties properties)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (properties.Items.TryGetValue(EveKeyPrefix + EveUserRefreshTokenKey, out var value) && !string.IsNullOrEmpty(value))
            {
                return value;
            }

            return null;
        }

        /// <summary>
        /// Store the value of a refresh token storage key.
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> properties.</param>
        /// <param name="key">The storage key.</param>
        public static void StoreRefreshTokenStorageKey(this AuthenticationProperties properties, string key)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (key.IsMissing())
            {
                throw new ArgumentException("Storage key cannot be null or empty.", nameof(key));
            }

            properties.Items[EveKeyPrefix + EveUserRefreshTokenKey] = key;
        }

        /// <summary>
        /// Checks that session id property is present in the <see cref="AuthenticationProperties"/> for correct work of EVE authentication.
        /// </summary>
        /// <param name="properties">The <see cref="AuthenticationProperties"/> properties.</param>
        public static bool ValidateSessionIdForEveOnline(this AuthenticationProperties properties)
        {
            return properties.GetUserSessionId().IsPresent();
        }

        public static bool ValidateStorageKeysForEveOnline(this AuthenticationProperties properties)
        {
            return properties.GetAccessTokenStorageKey().IsPresent() && properties.GetRefreshTokenStorageKey().IsPresent();
        }

        public static bool ValidateCookieTokensForEveOnline(this AuthenticationProperties properties)
        {
            var accessToken = properties.GetTokenValue("access_token");
            var refreshToken = properties.GetTokenValue("refresh_token");
            var expiresAtString = properties.GetTokenValue("expires_at");

            return accessToken.IsPresent() && refreshToken.IsPresent() && expiresAtString.IsPresent() && DateTimeOffset.TryParse(expiresAtString, out var _);
        }
    }
}
