using System.Collections.Generic;
using System.Linq;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public static class ListExtensions
    {
        /// <summary>
        /// Concatenates two sequences and only include each string value once.
        /// </summary>
        /// <param name="first">The first sequence to concatenate.</param>
        /// <param name="second">The sequence to concatenate to the first sequence.</param>
        public static List<string> ConcatOnce(this IEnumerable<string> first, IEnumerable<string> second)
        {
            var list = first != null ? new List<string>(first) : new List<string>();
            if (second?.Count() > 0)
            {
                list.AddRange(second.Where(vc => !list.Contains(vc)));
            }
            return list;
        }

        /// <summary>
        /// Concatenates two sequences and only include each string value once.
        /// </summary>
        /// <param name="first">The first sequence to concatenate.</param>
        /// <param name="second">The sequence to concatenate to the first sequence.</param>
        public static List<string> ConcatOnce(this List<string> first, List<string> second)
        {
            var list = first ?? new List<string>();
            if (second != null)
            {
                list.AddRange(second.Where(vc => !list.Contains(vc)));
            }
            return list;
        }
    }
}
