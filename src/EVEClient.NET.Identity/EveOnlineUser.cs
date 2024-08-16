namespace EVEClient.NET.Identity
{
    public class EveOnlineUser : IEveUser
    {
        public int CharacterId { get; set; }
        public string CharacterName { get; set; } = default!;
        public int CorporationId { get; set; }
        public string? PortraitUrl { get; set; }
        public int? AllianceId { get; set; }
    }
}
