namespace EVEClient.NET.Identity.Services
{
    public interface IUserClaimsTransformator
    {
        int Order { get; }

        Task TransformAsync(ClaimsTransformationContext context);
    }
}
