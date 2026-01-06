using System.Security.Cryptography.X509Certificates;
using Fido2NetLib;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
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

// Configure CORS options
builder.Services.Configure<CorsOptions>(
    builder.Configuration.GetSection(CorsOptions.SectionName));
var corsOptions = builder.Configuration.GetSection(CorsOptions.SectionName)
    .Get<CorsOptions>() ?? new CorsOptions();

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

// Add HTTP client for OIDC discovery with certificate validation
builder.Services.AddHttpClient("IdpClient")
    .ConfigurePrimaryHttpMessageHandler(() =>
    {
        var handler = new HttpClientHandler();
        
        // Load the IDP certificate from file (if provided) for validation
        X509Certificate2? idpCertificate = null;
        var idpCertPath = Environment.GetEnvironmentVariable("IDP_CERTIFICATE_PATH");
        if (!string.IsNullOrEmpty(idpCertPath) && File.Exists(idpCertPath))
        {
            try
            {
                idpCertificate = new X509Certificate2(idpCertPath);
                logger.LogInformation("Loaded IDP certificate from {IdpCertPath} for validation", idpCertPath);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to load IDP certificate from {IdpCertPath}, will use lenient validation", idpCertPath);
            }
        }
        
        // Configure certificate validation to trust our IDP certificate
        // In development, we'll accept certificates even with name mismatches if they match our certificate file
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
        {
            // If certificate is valid according to standard validation, accept it
            if (errors == System.Net.Security.SslPolicyErrors.None)
            {
                return true;
            }
            
            // For development: accept if we have the IDP certificate file and the cert matches
            if (idpCertificate != null && cert != null)
            {
                // Check if the certificate thumbprint matches (same certificate)
                var certHash = cert.GetCertHashString();
                var idpCertHash = idpCertificate.GetCertHashString();
                if (string.Equals(certHash, idpCertHash, StringComparison.OrdinalIgnoreCase))
                {
                    logger.LogDebug("Accepting certificate with mismatches - matches configured IDP certificate");
                    return true;
                }
                
                // Also check certificate chain to see if our certificate is in the chain
                if (chain != null && chain.ChainElements.Count > 0)
                {
                    foreach (var element in chain.ChainElements)
                    {
                        var chainCertHash = element.Certificate.GetCertHashString();
                        if (string.Equals(chainCertHash, idpCertHash, StringComparison.OrdinalIgnoreCase))
                        {
                            logger.LogDebug("Accepting certificate - configured IDP certificate found in chain");
                            return true;
                        }
                    }
                }
            }
            
            // For development: be lenient with certificate name mismatches if certificate chain is present
            // This allows self-signed certificates to work in Docker environments
            if ((errors == System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch ||
                 errors == (System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch | System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors)) &&
                chain != null && chain.ChainElements.Count > 0)
            {
                logger.LogDebug("Accepting certificate with name mismatch for development (Docker environment)");
                return true;
            }
            
            logger.LogWarning("Certificate validation failed. Errors: {Errors}", errors);
            return false;
        };
        
        return handler;
    });
builder.Services.AddScoped<OidcDiscoveryService>();

// Register WebAuthn services
// Credential Store: Use InMemoryWebAuthnCredentialStore for development/testing.
// For production, implement PersistentWebAuthnCredentialStore (e.g., Entity Framework, Dapper, etc.)
// and swap the registration below. The interface IWebAuthnCredentialStore abstracts the storage implementation.
// Example for persistent store: builder.Services.AddScoped<IWebAuthnCredentialStore, DatabaseWebAuthnCredentialStore>();
builder.Services.AddScoped<IWebAuthnCredentialStore, InMemoryWebAuthnCredentialStore>();
builder.Services.AddScoped<IIdpUserService, OidcIdpUserService>();
builder.Services.AddScoped<IWebAuthnService, WebAuthnService>();
builder.Services.AddScoped<IDPoPValidator, DPoPValidator>();
builder.Services.AddScoped<IJwtTokenValidator, JwtTokenValidator>();
builder.Services.AddScoped<ITokenExchangeService, TokenExchangeService>();

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        if (corsOptions.AllowedOrigins.Length > 0)
        {
            policy.WithOrigins(corsOptions.AllowedOrigins);
            
            if (corsOptions.AllowCredentials)
            {
                policy.AllowCredentials();
            }
        }
        else
        {
            // AllowAnyOrigin cannot be used with AllowCredentials
            policy.AllowAnyOrigin();
        }

        if (corsOptions.AllowAnyMethod)
        {
            policy.AllowAnyMethod();
        }

        if (corsOptions.AllowAnyHeader)
        {
            policy.AllowAnyHeader();
        }
    });
});

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

// Enable CORS (before other middleware)
app.UseCors("AllowFrontend");

// Add DPoP validation middleware (before authorization)
app.UseMiddleware<PassKeySample.Api.Middleware.DPoPValidationMiddleware>();

app.UseAuthorization();
app.MapControllers();

app.Run();

