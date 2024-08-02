using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace EVEClient.NET.Identity.Extensions
{
    public static class StringExtensions
    {
        public static string TrimHttpScheme([StringSyntax(StringSyntaxAttribute.Uri)] this string url)
        {
            if (!string.IsNullOrEmpty(url) && Uri.TryCreate(url, UriKind.Absolute, out var result))
            {
                return result.Host;
            }

            return url;
        }
        
        public static bool IsMissing([NotNullWhen(false)] this string? @this)
        {
            return string.IsNullOrEmpty(@this) || string.IsNullOrWhiteSpace(@this);
        }

        public static bool IsPresent([NotNullWhen(true)] this string? @this)
        {
            return !@this.IsMissing();
        }

        public static string EnshureEveSubjectNormalized(this string subject)
        {
            if (!string.IsNullOrEmpty(subject) && subject.StartsWith("CHARACTER:EVE:", StringComparison.OrdinalIgnoreCase))
            {
                return subject.Replace("CHARACTER:EVE:", string.Empty, StringComparison.OrdinalIgnoreCase);
            }

            return subject;
        }

        public static Stream GetStreamWithGetBytes(this string value, Encoding? encoding = null)
        {
            encoding ??= Encoding.UTF8;
            var byteArray = encoding.GetBytes(value);
            var memoryStream = new MemoryStream(byteArray);

            return memoryStream;
        }
    }
}
