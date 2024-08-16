using Microsoft.AspNetCore.Authentication;

namespace EVEClient.NET.Identity.Extensions
{
    public static class AuthenticationPropertiesExtensions
    {
        private const string EveKeyPrefix = ".eve.";
        private const string EveAccessTokenReferenceKey = "token.access";
        private const string EveRefreshTokenReferenceKey = "token.refresh";
        private const string EveUserSessionKey = "session";

        public static void StoreEveAccessTokenReferenceKey(this AuthenticationProperties properties, string referenceId)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (referenceId.IsMissing())
            {
                throw new ArgumentException("ReferenceId cannot be null or empty.", nameof(referenceId));
            }

            properties.Items[EveKeyPrefix + EveAccessTokenReferenceKey] = referenceId;
        }

        public static void StoreEveRefreshTokenReferenceKey(this AuthenticationProperties properties, string referenceId)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (referenceId.IsMissing())
            {
                throw new ArgumentException("ReferenceId cannot be null or empty.", nameof(referenceId));
            }

            properties.Items[EveKeyPrefix + EveRefreshTokenReferenceKey] = referenceId;
        }

        public static string? GetEveRefreshTokenReferenceKey(this AuthenticationProperties properties)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (properties.Items.TryGetValue(EveKeyPrefix + EveRefreshTokenReferenceKey, out var value) && !string.IsNullOrEmpty(value))
            {
                return value;
            }

            return null;
        }

        public static string? GetEveAccessTokenReferenceKey(this AuthenticationProperties properties)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (properties.Items.TryGetValue(EveKeyPrefix + EveAccessTokenReferenceKey, out var value) && !string.IsNullOrEmpty(value))
            {
                return value;
            }

            return null;
        }

        public static string? GetUserSessionId(this AuthenticationProperties properties)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (properties.Items.TryGetValue(EveKeyPrefix + EveUserSessionKey, out var value) && !string.IsNullOrEmpty(value))
            {
                return value;
            }

            return null;
        }

        public static void StoreUserSessionId(this AuthenticationProperties properties, string sessionId)
        {
            ArgumentNullException.ThrowIfNull(properties);

            if (sessionId.IsMissing())
            {
                throw new ArgumentException("SessionId cannot be null or empty.", nameof(sessionId));
            }

            properties.Items[EveKeyPrefix + EveUserSessionKey] = sessionId;
        }
    }
}
