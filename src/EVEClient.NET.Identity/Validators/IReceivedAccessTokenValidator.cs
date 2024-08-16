namespace EVEClient.NET.Identity.Validators
{
    public interface IReceivedAccessTokenValidator
    {
        Task<AccessTokenValidationResult> ValidateAsync(string accessToken);
    }
}
