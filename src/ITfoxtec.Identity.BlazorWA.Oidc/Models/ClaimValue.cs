namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect.Models
{
    public class ClaimValue
    {
        public string Type { get; set; }
        public string Value { get; set; }
        public string ValueType { get; set; }
        public string Issuer { get; set; }
        public string OriginalIssuer { get; set; }
    }
}
