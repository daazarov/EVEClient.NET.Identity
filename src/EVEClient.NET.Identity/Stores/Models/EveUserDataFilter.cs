namespace EVEClient.NET.Identity.Stores
{
    public class EveUserDataFilter
    {
        /// <summary>
        /// Sets the data type to be filtered for.
        /// </summary>
        public string DataType { get; init; } = default!;

        /// <summary>
        /// Sets the subject id (aka EVE chatacter ID) to be filtered for.
        /// </summary>
        public string? SubjectId { get; init; }

        /// <summary>
        /// Sets the session id to be filtered for.
        /// </summary>
        public string? SessionId { get; init; }
    }
}
