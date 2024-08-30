using System.Diagnostics.CodeAnalysis;

using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Configuration
{
    public class TokenHandlerConfiguration : IEqualityComparer<TokenHandlerConfiguration>
    {
        /// <summary>
        /// Gets or sets authentication scheme name associated with token handler.
        /// </summary>
        public string Scheme { get; set; } = default!;

        /// <summary>
        /// Gets or sets token handler type.
        /// </summary>
        public Type HandlerType { get; set; } = default!;

        /// <summary>
        /// Gets or sets token type associated with token handler.
        /// </summary>
        public string TokenType { get; set; } = default!;

        public void Validate()
        {
            if (Scheme.IsMissing())
            {
                throw new InvalidOperationException("Scheme name can not be null or empty.");
            }

            if (TokenType.IsMissing())
            {
                throw new InvalidOperationException("Assigned token type name can not be null or empty.");
            }

            if (HandlerType == null)
            {
                throw new InvalidOperationException("HandlerType can not be null or empty.");
            }
        }

        public bool Equals(TokenHandlerConfiguration? x, TokenHandlerConfiguration? y)
        {
            if ((x == null && y != null) || (x != null && y == null))
            {
                return false;
            }
            
            return x?.Scheme == y?.Scheme && x?.TokenType == y?.TokenType;
        }

        public int GetHashCode([DisallowNull] TokenHandlerConfiguration obj)
        {
            return (Scheme, TokenType).GetHashCode();
        }
    }
}
