using Fido2NetLib;
using Microsoft.Extensions.Caching.Memory;
using PassKeySample.Api.Configuration;
using PassKeySample.Api.Extensions;
using PassKeySample.Api.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add memory cache for credential storage and challenge cache
builder.Services.AddMemoryCache();

// Configure Identity Provider options
builder.Services.Configure<IdentityProviderOptions>(
    builder.Configuration.GetSection(IdentityProviderOptions.SectionName));
builder.Services.AddSingleton(builder.Configuration.GetSection(IdentityProviderOptions.SectionName)
    .Get<IdentityProviderOptions>() ?? new IdentityProviderOptions());

// Configure WebAuthn options
builder.Services.Configure<WebAuthnOptions>(
    builder.Configuration.GetSection(WebAuthnOptions.SectionName));
var webauthnOptions = builder.Configuration.GetSection(WebAuthnOptions.SectionName)
    .Get<WebAuthnOptions>() ?? new WebAuthnOptions();

// Configure Fido2NetLib
builder.Services.AddSingleton<IFido2>(serviceProvider =>
{
    var logger = serviceProvider.GetRequiredService<ILogger<Fido2>>();
    return new Fido2(new Fido2Configuration
    {
        ServerDomain = webauthnOptions.RpId,
        ServerName = webauthnOptions.RpName,
        Origins = new HashSet<string> { webauthnOptions.Origin },
        TimestampDriftTolerance = webauthnOptions.Timeout // In milliseconds
    });
});

// Configure HttpClient to trust IDP certificate from environment variable
// In dev: points to keycloak.crt, in production: customer-provided certificate (root CA or self-signed)
using var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
var logger = loggerFactory.CreateLogger<Program>();
builder.Services.ConfigureIdpCertificateTrust(logger);

// Add HTTP client for OIDC discovery
builder.Services.AddHttpClient();
builder.Services.AddScoped<OidcDiscoveryService>();

// Register WebAuthn services
builder.Services.AddScoped<IWebAuthnCredentialStore, InMemoryWebAuthnCredentialStore>();
builder.Services.AddScoped<IIdpUserService, OidcIdpUserService>();
builder.Services.AddScoped<IWebAuthnService, WebAuthnService>();
builder.Services.AddScoped<IDPoPValidator, DPoPValidator>();

// Configure HTTPS
builder.Services.AddHttpsRedirection(options =>
{
    options.RedirectStatusCode = StatusCodes.Status307TemporaryRedirect;
    options.HttpsPort = 5001;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Add DPoP validation middleware (before authorization)
app.UseMiddleware<PassKeySample.Api.Middleware.DPoPValidationMiddleware>();

app.UseAuthorization();
app.MapControllers();

app.Run();

