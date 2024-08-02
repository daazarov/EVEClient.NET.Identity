namespace EVEClient.NET.Identity
{
    public class EveClaims
    {
        public static class Issuers
        {
            public const string Audience = "aud";
            public const string Subject = "sub";
            public const string Name = "name";
            public const string Owner = "owner";
            public const string KeyId = "kid";
            public const string Region = "region";
            public const string Tier = "tier";
            public const string Tenant = "tenant";
            public const string JwtId = "jti";
            public const string AuthrizedParty = "azp";
            public const string Scope = "scp";
            public const string Expiration = "exp";
            public const string Issuer = "iss";
            public const string IssuedAt = "iat";
        }

        public static class Custom
        {
            public const string Corporation = "eve:character:corp";
            public const string Alliance = "eve:character:alliance";
            public const string Description = "eve:character:desc";
            public const string Title = "eve:character:title";
        }
    }
}
