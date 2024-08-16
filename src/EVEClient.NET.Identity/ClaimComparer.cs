using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace EVEClient.NET.Identity
{
    public class ClaimComparer : IEqualityComparer<Claim>
    {
        public bool Equals(Claim? x, Claim? y)
        {
            ArgumentNullException.ThrowIfNull(x);
            ArgumentNullException.ThrowIfNull(y);

            if (x == null && y == null) return true;
            if (x == null && y != null) return false;
            if (x != null && y == null) return false;

            return string.Equals(x!.Type, y!.Type!, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(x!.Value, y!.Value, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(x!.ValueType, y!.ValueType, StringComparison.Ordinal);
        }

        public int GetHashCode([DisallowNull] Claim obj)
        {
            if (obj is null) return 0;

            return obj.Type.GetHashCode() ^ obj.Value.GetHashCode() ^ obj.ValueType?.GetHashCode() ?? 0;
        }
    }
}
