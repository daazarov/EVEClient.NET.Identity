using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EVEClient.NET.Identity
{
    public static class OAuthConstants
    {
        public static class TokenRequest
        {
            public const string GrantType = "grant_type";
            public const string ClientId = "client_id";
            public const string ClientSecret = "client_secret";
            public const string RefreshToken = "refresh_token";
            public const string Scope = "scope";
            public const string Token = "token";
            public const string TokenTypeHint = "token_type_hint";
        }


        public static class TokenResponse
        {
            public const string AccessToken = "access_token";
            public const string ExpiresIn = "expires_in";
            public const string TokenType = "token_type";
            public const string RefreshToken = "refresh_token";
            public const string Error = "error";
            public const string ErrorDescription = "error_description";
        }

        public static class TokenTypes
        {
            public const string AccessToken = "access_token";
            public const string RefreshToken = "refresh_token";
        }
    }
}
