using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.OAuth
{
    public class Parameters : List<KeyValuePair<string, string>>
    {
        public void Add(string key, string value)
        {
            if (key.IsMissing())
            { 
                throw new ArgumentNullException(nameof(key));
            }

            var existingParameters = this.Where(x => x.Key == key).ToList();
            if (existingParameters.Count > 0)
            {
                existingParameters.ForEach(x => this.Remove(x));
            }

            Add(KeyValuePair.Create(key, value));
        }

        public string Extract(string key, bool keep = false)
        {
            if (!ContainsKey(key))
            {
                throw new KeyNotFoundException(key);
            }

            var kvp = this.Where(x => x.Key.Equals(key)).First();

            if (!keep) this.Remove(kvp);

            return kvp.Value;
        }

        public bool ContainsKey(string key)
        {
            return this.Any(x => x.Key.Equals(key));
        }
    }
}
