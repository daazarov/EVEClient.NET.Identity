namespace EVEClient.NET.Identity.Stores
{
    public interface IStorageKeyGenerator
    {
        string GenerateKey(int length = 32);
    }
}
