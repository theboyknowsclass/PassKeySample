using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PassKeySample.Api.Extensions;

public static class HttpClientExtensions
{
    /// <summary>
    /// Configures HttpClient to trust an IDP certificate from an environment variable.
    /// Works with both self-signed certificates and root CA certificates.
    /// In production, customers can provide their root CA or self-signed certificate.
    /// </summary>
    public static void ConfigureIdpCertificateTrust(this IServiceCollection services, ILogger logger)
    {
        var idpCertPath = Environment.GetEnvironmentVariable("IDP_CERTIFICATE_PATH");
        
        if (string.IsNullOrEmpty(idpCertPath))
        {
            logger.LogInformation("IDP_CERTIFICATE_PATH not set, skipping IDP certificate trust configuration");
            return;
        }

        if (!File.Exists(idpCertPath))
        {
            logger.LogWarning("IDP certificate file not found at: {IdpCertPath}", idpCertPath);
            return;
        }

        try
        {
            // Read the certificate (could be self-signed or a root CA)
            // For .crt files, use the constructor directly
            var cert = new X509Certificate2(idpCertPath);
            
            // Add the certificate to the certificate store so HttpClient will trust it
            // Use LocalMachine for Linux containers, CurrentUser for Windows
            var storeLocation = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) 
                ? StoreLocation.CurrentUser 
                : StoreLocation.LocalMachine;
            var store = new X509Store(StoreName.Root, storeLocation);
            store.Open(OpenFlags.ReadWrite);
            try
            {
                // Check if certificate already exists
                var existingCerts = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    cert.Thumbprint,
                    false);
                
                if (existingCerts.Count == 0)
                {
                    store.Add(cert);
                    logger.LogInformation("Added IDP certificate to trust store from: {IdpCertPath}", idpCertPath);
                }
                else
                {
                    logger.LogInformation("IDP certificate already exists in trust store");
                }
            }
            finally
            {
                store.Close();
            }
            
            logger.LogInformation("Successfully configured HttpClient to trust IDP certificate from: {IdpCertPath}", idpCertPath);
        }
        catch (Exception ex)
        {
            // In Docker/Linux environments, the system certificate store is read-only
            // This is expected behavior. Certificate validation will be handled via
            // ServerCertificateCustomValidationCallback in HttpClient configuration.
            if (ex is CryptographicException && 
                (ex.InnerException is PlatformNotSupportedException || 
                 ex.Message.Contains("read-only", StringComparison.OrdinalIgnoreCase)))
            {
                logger.LogInformation(
                    "Cannot add certificate to system store (read-only in Docker/Linux environment). " +
                    "Certificate validation will be handled via HttpClient callback. Certificate path: {IdpCertPath}", 
                    idpCertPath);
            }
            else
            {
                logger.LogWarning(ex, "Failed to configure IDP certificate trust from: {IdpCertPath}. " +
                                     "Certificate validation will be handled via HttpClient callback.", idpCertPath);
            }
            // Don't throw - allow the application to continue without custom certificate trust
        }
    }
}

