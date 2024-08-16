using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Web;

namespace EVEClient.NET.Identity.Extensions
{
    public static class StringExtensions
    {
        [DebuggerStepThrough]
        public static string TrimHttpScheme([StringSyntax(StringSyntaxAttribute.Uri)] this string url)
        {
            if (!string.IsNullOrEmpty(url) && Uri.TryCreate(url, UriKind.Absolute, out var result))
            {
                return result.Host;
            }

            return url;
        }

        [DebuggerStepThrough]
        public static bool IsMissing([NotNullWhen(false)] this string? @this)
        {
            return string.IsNullOrEmpty(@this) || string.IsNullOrWhiteSpace(@this);
        }

        [DebuggerStepThrough]
        public static bool IsPresent([NotNullWhen(true)] this string? @this)
        {
            return !@this.IsMissing();
        }

        [DebuggerStepThrough]
        public static string EnshureEveSubjectNormalized(this string subject)
        {
            if (!string.IsNullOrEmpty(subject) && subject.StartsWith("CHARACTER:EVE:", StringComparison.OrdinalIgnoreCase))
            {
                return subject.Replace("CHARACTER:EVE:", string.Empty, StringComparison.OrdinalIgnoreCase);
            }

            return subject;
        }

        [DebuggerStepThrough]
        internal static string RemoveQueryStringByKey([StringSyntax(StringSyntaxAttribute.Uri)] this string url, string key)
        {
            var uri = new Uri(url);
            var newQueryString = HttpUtility.ParseQueryString(uri.Query);
            var pagePathWithoutQueryString = uri.GetLeftPart(UriPartial.Path);

            newQueryString.Remove(key);

            return newQueryString.Count > 0
                ? String.Format("{0}?{1}", pagePathWithoutQueryString, newQueryString)
                : pagePathWithoutQueryString;
        }
    }
}
