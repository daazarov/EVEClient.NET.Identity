using System.Diagnostics.CodeAnalysis;

namespace EVEClient.NET.Identity.Extensions
{
    public static class CollectionExtensions
    {
        public static void AddRange<T>([NotNull] this ICollection<T> @this, [NotNull] IEnumerable<T> range)
        {
            foreach (var item in range)
            {
                @this.Add(item);
            }
        }

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

        public static bool IsMissing<T>([NotNullWhen(false)] this ICollection<T>? collection)
        {
            return !collection.IsPresent();
        }

        public static bool In<T>(this T @this, params T[] items)
        {
            return items.Contains(@this);
        }

        public static bool NotIn<T>(this T @this, params T[] items)
        {
            return !items.Contains(@this);
        }
    }
}
