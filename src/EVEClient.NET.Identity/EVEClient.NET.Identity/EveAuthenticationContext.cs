namespace EVEClient.NET.Identity
{
    public class EveAuthenticationContext
    {
        internal EveAuthenticationContext()
        { }

        public string SubjectId { get; internal set; } = default!;

        public string SessionId { get; internal set; } = default!;

        public string AccessTokenReferenceKey { get; internal set; } = default!;

        public string RefreshTokenReferenceKey { get; internal set; } = default!;
    }
}
