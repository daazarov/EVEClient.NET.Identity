using System.Security.Claims;

namespace EVEClient.NET.Identity.Extensions
{
    public static class ClaimExtensions
    {
        public static int AsInteger(this Claim claim)
        {
            if (int.TryParse(claim.Value, out var value))
            {
                return value;
            }

            throw new InvalidCastException($"Cannot convert a value ({claim.Value}) to integer.");
        }

        public static DateTime AsDateTime(this Claim claim)
        {
            if (DateTime.TryParse(claim.Value, out var value))
            {
                return value;
            }

            throw new InvalidCastException($"Cannot convert a value ({claim.Value}) to date.");
        }
    }
}
