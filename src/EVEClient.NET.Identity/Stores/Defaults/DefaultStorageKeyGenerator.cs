using System.Security.Cryptography;
using System.Text;

namespace EVEClient.NET.Identity.Stores
{
    public class DefaultStorageKeyGenerator : IStorageKeyGenerator
    {
        internal static readonly char[] chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_=+".ToCharArray();

        public string GenerateKey(int length = 32)
        {
            var data = new byte[4 * length];
            var result = new StringBuilder(length);

            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(data);
            }

            for (int i = 0; i < length; i++)
            {
                var rnd = BitConverter.ToUInt32(data, i * 4);
                var idx = rnd % chars.Length;

                result.Append(chars[idx]);
            }

            return result.ToString();
        }
    }
}
