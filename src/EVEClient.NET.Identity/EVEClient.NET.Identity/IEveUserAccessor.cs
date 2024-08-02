namespace EVEClient.NET.Identity
{
    public interface IEveUserAccessor<TUser> where TUser : class, IEveUser
    {
        TUser? User { get; }
    }
}
