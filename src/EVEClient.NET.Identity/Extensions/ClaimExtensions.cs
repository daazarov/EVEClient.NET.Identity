using System.Diagnostics;
using System.Security.Claims;

namespace EVEClient.NET.Identity.Extensions
{
    public static class ClaimExtensions
    {
        /// <summary>
        /// Converts the claim value to integer.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/>.</param>
        /// <exception cref="InvalidCastException"></exception>
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
