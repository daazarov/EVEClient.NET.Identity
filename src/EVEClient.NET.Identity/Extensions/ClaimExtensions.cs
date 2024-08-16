using System.Diagnostics;
using System.Security.Claims;

namespace EVEClient.NET.Identity.Extensions
{

    public static class ClaimExtensions
    {
        [DebuggerStepThrough]
        public static int AsInteger(this Claim claim)
        {
            if (int.TryParse(claim.Value, out var value))
            {
                return value;
            }

            throw new InvalidCastException($"Cannot convert a value ({claim.Value}) to integer.");
        }
    }
}
