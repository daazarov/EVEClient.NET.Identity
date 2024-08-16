namespace EVEClient.NET.Identity.Services
{
    public interface IUserClaimsTransformator
    {
        Task TransformAsync(ClaimsTransformationContext context);
    }
}
