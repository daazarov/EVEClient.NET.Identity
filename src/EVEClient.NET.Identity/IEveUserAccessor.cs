using System.Diagnostics.CodeAnalysis;

using EVEClient.NET.Identity.Configuration;

namespace EVEClient.NET.Identity
{
    public interface IEveUserAccessor<TUser> where TUser : class, IEveUser
    {
        /// <summary>
        /// Indicates whether there is an authenticated EVE user regardless of the <see cref="IdentityMode"/>.
        /// </summary>
        [MemberNotNullWhen(true, nameof(Current))]
        bool IsAuthenticated { get; }
        
        /// <summary>
        /// Gets the current EVE user.
        /// </summary>
        TUser? Current { get; }
    }
}
