namespace EVEClient.NET.Identity.Configuration
{
    public class IssuerClaimsOptions
    {
        /// <summary>
        /// Adds EVE claim with <see cref="EveClaims.Issuers.Region"/> name to the final Identity.
        /// </summary>
        /// <remarks>Default value: true</remarks>
        public bool RegionEnable { get; set; } = true;

        /// <summary>
        /// Adds EVE claim with <see cref="EveClaims.Issuers.Issuer"/> name to the final Identity.
        /// </summary>
        /// <remarks>Default value: true</remarks>
        public bool IssuerEnable { get; set; } = true;

        /// <summary>
        /// Adds EVE claim with <see cref="EveClaims.Issuers.Tier"/> name to the final Identity.
        /// </summary>
        /// <remarks>Default value: true</remarks>
        public bool TierEnable { get; set; } = true;

        /// <summary>
        /// Adds EVE claim with <see cref="EveClaims.Issuers.Tenant"/> name to the final Identity.
        /// </summary>
        /// <remarks>Default value: true</remarks>
        public bool TenantEnable { get; set; } = true;

        /// <summary>
        /// Adds EVE claim with <see cref="EveClaims.Issuers.JwtId"/> name to the final Identity.
        /// </summary>
        /// <remarks>Default value: false</remarks>
        public bool JwtIdEnable { get; set; } = false;

        /// <summary>
        /// Adds EVE claim with <see cref="EveClaims.Issuers.Owner"/> name to the final Identity.
        /// </summary>
        /// <remarks>Default value: false</remarks>
        public bool OwnerEnable { get; set; } = false;

        /// <summary>
        /// Adds EVE claim with <see cref="EveClaims.Issuers.Audience"/> name to the final Identity.
        /// </summary>
        /// <remarks>Default value: false</remarks>
        public bool AudienceEnable { get; set; } = false;

        /// <summary>
        /// Adds EVE claim with <see cref="EveClaims.Issuers.AuthrizedParty"/> name to the final Identity.
        /// </summary>
        /// <remarks>Default value: false</remarks>
        public bool AuthrizedPartyEnable { get; set; } = false;

        /// <summary>
        /// Adds EVE claim with <see cref="EveClaims.Issuers.KeyId"/> name to the final Identity.
        /// </summary>
        /// <remarks>Default value: false</remarks>
        public bool KeyIdEnable { get; set; } = false;
    }
}
