namespace PassKeySample.Api.Configuration;

public class WebAuthnOptions
{
    public const string SectionName = "WebAuthn";

    public string RpId { get; set; } = "localhost";
    public string RpName { get; set; } = "PassKey Sample";
    public string Origin { get; set; } = "https://localhost:3000";
    public int Timeout { get; set; } = 60000; // 60 seconds
}

