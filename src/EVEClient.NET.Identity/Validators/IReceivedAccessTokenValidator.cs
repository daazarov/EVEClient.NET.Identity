namespace EVEClient.NET.Identity.Validators
{
    public interface IReceivedAccessTokenValidator
    {
        /// <summary>
        /// Validate recieved JWT access token.
        /// </summary>
        /// <param name="accessToken">The access token value.</param>
        /// <returns>The <see cref="AccessTokenValidationResult"/> instance.</returns>
        Task<AccessTokenValidationResult> ValidateAsync(string accessToken);
    }
}
