using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EVEClient.NET.Identity.Stores
{
    public interface IStorageKeyGenerator
    {
        string GenerateKey(string subjectId, string sessionId, string dataType);
    }
}
