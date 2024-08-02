using System.Diagnostics.CodeAnalysis;

namespace EVEClient.NET.Identity.Extensions
{
    public static class NullableTypesExtensions
    {
        public static bool IsPresent<T>([NotNullWhen(true)] this T? @this) where T : struct
        { 
            return @this.HasValue;
        }
    }
}
