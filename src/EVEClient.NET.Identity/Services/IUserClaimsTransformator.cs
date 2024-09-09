namespace EVEClient.NET.Identity.Services
{
    public interface IUserClaimsTransformator
    {
        /// <summary>
        /// Provides a central transformation point to change the specified claim collection.
        /// </summary>
        /// <param name="context">The <see cref="ClaimsTransformationContext"/>.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task TransformAsync(ClaimsTransformationContext context);
    }
}
