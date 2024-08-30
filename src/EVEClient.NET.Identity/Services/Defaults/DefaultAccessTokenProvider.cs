using Microsoft.AspNetCore.Http;

using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultAccessTokenProvider : IAccessTokenProvider
    {
        private readonly ITokenService _tokenService;
        private readonly IHttpContextAccessor _contextAccessor;
        
        public DefaultAccessTokenProvider(ITokenService tokenService, IHttpContextAccessor httpContextAccessor)
        { 
            _tokenService = tokenService;
            _contextAccessor = httpContextAccessor;
        }

        public async Task<string> RequestAccessToken()
        {
            if (_contextAccessor.HttpContext == null)
                throw new NotSupportedException("DefaultAccessTokenProvider: Executing context exception, HttpContext can not be null.");

            return await _contextAccessor.HttpContext.GetEveAccessTokenAsync() ?? string.Empty;
        }
    }
}
