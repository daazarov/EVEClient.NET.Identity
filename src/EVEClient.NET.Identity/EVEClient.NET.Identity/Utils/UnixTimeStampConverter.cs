using EVEClient.NET.Identity.Extensions;
using System.Globalization;

namespace EVEClient.NET.Identity.Utils
{
    public static class UnixTimeStampConverter
    {
        public static DateTimeOffset UnixTimeStampToDateTime(string seconds)
        {
            if (seconds.IsPresent())
            {
                if (long.TryParse(seconds, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    // https://www.w3.org/TR/xmlschema-2/#dateTime
                    // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                    var date = DateTimeOffset.FromUnixTimeSeconds(value);

                    return date;
                }
            }

            throw new InvalidOperationException($"{nameof(seconds)} can not be null or empty.");
        }

        public static DateTimeOffset FromExpiresInUnixTimeStampToExpiresAtDateTime(string expiresIn)
        {
            if (expiresIn.IsPresent())
            {
                if (long.TryParse(expiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    // https://www.w3.org/TR/xmlschema-2/#dateTime
                    // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                    var expiresAt = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(value);

                    return expiresAt;
                }
            }

            throw new InvalidOperationException($"{nameof(expiresIn)} can not be null or empty.");
        }
    }
}
