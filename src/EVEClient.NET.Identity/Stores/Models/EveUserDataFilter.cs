namespace EVEClient.NET.Identity.Stores
{
    public class EveUserDataFilter
    {
        public string DataType { get; init; } = default!;
        
        public string? SubjectId { get; init; }

        public string? SessionId { get; init; }
    }
}
