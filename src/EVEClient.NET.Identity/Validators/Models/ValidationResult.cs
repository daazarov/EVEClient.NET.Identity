using System.Diagnostics.CodeAnalysis;

namespace EVEClient.NET.Identity.Validators
{
    public class ValidationResult
    {
        [MemberNotNullWhen(false, nameof(Error))]
        public virtual bool Succeeded { get; protected set; }

        public string? Error { get; protected set; }
    }
}
