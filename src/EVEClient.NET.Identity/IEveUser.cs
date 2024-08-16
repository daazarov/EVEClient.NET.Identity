namespace EVEClient.NET.Identity
{
    public interface IEveUser
    {
        public int CharacterId { get; set; }
        public string CharacterName { get; set; }
    }
}
