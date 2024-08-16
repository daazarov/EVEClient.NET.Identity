namespace EVEClient.NET.Identity.Stores
{
    public class EveUserData
    {
        public string Key { get; set; } = default!;

        public string Type { get; set; } = default!;

        public string Data { get; set; } = default!;

        public string SessionId { get; set; } = default!;

        public string SubjectId { get; set; } = default!;

        public DateTimeOffset CreationTime { get; set; } = DateTimeOffset.Now;

        public DateTimeOffset? Expiration { get; set; }
    }
}
