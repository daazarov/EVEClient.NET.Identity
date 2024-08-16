namespace EVEClient.NET.Identity.Services
{
    public class PostOAuthBehaviorResult
    {
        public virtual bool Succeeded => Error == null;
        public Exception? Error { get; internal set; }
        public Dictionary<string, object> Properties { get; set; } = new();

        protected PostOAuthBehaviorResult()
        {
        }

        public static PostOAuthBehaviorResult Success()
        {
            return new PostOAuthBehaviorResult();
        }

        public static PostOAuthBehaviorResult Failed(Exception exception)
        {
            return new PostOAuthBehaviorResult { Error = exception};
        }
    }
}
