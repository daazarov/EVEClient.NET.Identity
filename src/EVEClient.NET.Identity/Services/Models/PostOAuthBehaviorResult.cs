namespace EVEClient.NET.Identity.Services
{
    public class PostOAuthBehaviorResult
    {
        /// <summary>
        /// Indicates whether the behavior result is successful.
        /// </summary>
        public virtual bool Succeeded => Error == null;

        /// <summary>
        /// Gets the <see cref="Exception"/>.
        /// </summary>
        public Exception? Error { get; protected set; }

        /// <summary>
        /// Gets the <see cref="Dictionary{string, object}}"/> for storing custom objects if needed.
        /// </summary>
        public Dictionary<string, object> Properties { get; } = new();

        protected PostOAuthBehaviorResult()
        {
        }

        /// <summary>
        /// Creates a succeeded <see cref="PostOAuthBehaviorResult"/>.
        /// </summary>
        /// <returns>The <see cref="PostOAuthBehaviorResult"/> instance.</returns>
        public static PostOAuthBehaviorResult Success()
        {
            return new PostOAuthBehaviorResult();
        }

        /// <summary>
        /// Creates a failed <see cref="PostOAuthBehaviorResult"/>.
        /// </summary>
        /// <param name="exception">The <see cref="Exception"/>.</param>
        /// <returns>The <see cref="PostOAuthBehaviorResult"/> instance.</returns>
        public static PostOAuthBehaviorResult Failed(Exception exception)
        {
            return new PostOAuthBehaviorResult { Error = exception };
        }
    }
}
