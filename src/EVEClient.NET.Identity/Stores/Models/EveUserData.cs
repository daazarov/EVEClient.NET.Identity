namespace EVEClient.NET.Identity.Stores
{
    public class EveUserData
    {
        /// <summary>
        ///  Gets or sets the data key.
        /// </summary>
        public string Key { get; set; } = default!;

        /// <summary>
        /// Gets or sets the data type.
        /// </summary>
        public string Type { get; set; } = default!;

        /// <summary>
        /// Gets or sets the user data as serialized string.
        /// </summary>
        public string Data { get; set; } = default!;

        /// <summary>
        /// Gets or sets the session id that associate with user data.
        /// </summary>
        public string SessionId { get; set; } = default!;

        /// <summary>
        /// Gets or sets the subject id (aka EVE character ID).
        /// </summary>
        public string SubjectId { get; set; } = default!;

        /// <summary>
        /// Gets or sets the creation time of the user data.
        /// </summary>
        public DateTimeOffset CreationTime { get; set; } = DateTimeOffset.Now;

        /// <summary>
        /// Gets or sets the expiration time of the user data.
        /// </summary>
        public DateTimeOffset? Expiration { get; set; }
    }
}
