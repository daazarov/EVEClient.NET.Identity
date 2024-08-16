namespace EVEClient.NET.Identity
{
    public class EveAuthenticationContext
    {
        internal EveAuthenticationContext()
        { }

        public string SubjectId { get; init; } = default!;

        public string SessionId { get; init; } = default!;

        public string AccessTokenReferenceKey { get; init; } = default!;

        public string RefreshTokenReferenceKey { get; init; } = default!;
    }
}
