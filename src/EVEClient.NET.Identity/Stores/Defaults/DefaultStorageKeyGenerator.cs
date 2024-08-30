using EVEClient.NET.Extensions;
using EVEClient.NET.Identity.Stores;

namespace EVEClient.NET.Identity.Stores
{
    public class DefaultStorageKeyGenerator : IStorageKeyGenerator
    {
        private const string Separator = ":";

        public string GenerateKey(string subjectId, string sessionId, string dataType)
        {
            return string.Join(Separator, subjectId, sessionId, dataType).SHA256();
        }
    }
}
