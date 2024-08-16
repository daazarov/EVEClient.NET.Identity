using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace EVEClient.NET.Identity.Extensions
{
    public static class CollectionExtensions
    {
        [DebuggerStepThrough]
        public static void AddRange<T>([NotNull] this ICollection<T> @this, [NotNull] IEnumerable<T> range)
        {
            foreach (var item in range)
            {
                @this.Add(item);
            }
        }

        [DebuggerStepThrough]
        public static bool IsPresent<T>([NotNullWhen(true)] this ICollection<T>? collection)
        {
            if (collection is null)
            {
                return false;
            }

            if (collection.Count == 0)
            {
                return false;
            }

            return true;
        }

        [DebuggerStepThrough]
        public static bool IsMissing<T>([NotNullWhen(false)] this ICollection<T>? collection)
        {
            return !collection.IsPresent();
        }

        [DebuggerStepThrough]
        public static bool In<T>(this T @this, params T[] items)
        {
            return items.Contains(@this);
        }

        [DebuggerStepThrough]
        public static bool NotIn<T>(this T @this, params T[] items)
        {
            return !items.Contains(@this);
        }
    }
}
