using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SBCertUtils
{
    public static class CertUtils
    {
        const string RSA = "1.2.840.113549.1.1.1";
        const string DSA = "1.2.840.10040.4.1";
        const string ECC = "1.2.840.10045.2.1";
        
        public static void PrintCert(this X509Certificate2 cert, string certName = null)
        {
            if (certName != null)
                Console.WriteLine($"***** cert {certName} *****");
            Console.WriteLine($"Has Private Key = {cert.HasPrivateKey}");
            Console.WriteLine($"PublicKey OID = {cert.PublicKey.Oid.Value}");
            switch (cert.PublicKey.Oid.Value) {
                case RSA:
                    RSA_Label:
                    RSA rsa = cert.GetRSAPrivateKey(); // or cert.GetRSAPublicKey() when need public key
                    Console.WriteLine($"Got RSA PrivateKey = {rsa}, SignatureAlgorithm = {rsa.SignatureAlgorithm}, KeyExchangeAlgorithm = {rsa.KeyExchangeAlgorithm}, KeySize = {rsa.KeySize}");
                    // use the key
                    break;
                case DSA:
                    DSA dsa = cert.GetDSAPrivateKey(); // or cert.GetDSAPublicKey() when need public key
                    Console.WriteLine($"Got DSA PrivateKey = {dsa}, SignatureAlgorithm = {dsa.SignatureAlgorithm}, KeyExchangeAlgorithm = {dsa.KeyExchangeAlgorithm}, KeySize = {dsa.KeySize}");
                    // use the key
                    break;
                case ECC:
                    ECDsa ecc = cert.GetECDsaPrivateKey(); // or cert.GetECDsaPublicKey() when need public key
                    if (ecc == null)
                    {
                        Console.WriteLine("ecc was null, will do RSA");
                        goto RSA_Label;
                    }
                    Console.WriteLine($"Got ECC PrivateKey = {ecc}, SignatureAlgorithm = {ecc.SignatureAlgorithm}, KeyExchangeAlgorithm = {ecc.KeyExchangeAlgorithm}, KeySize = {ecc.KeySize}");
                    // use the key
                    break;
            }
        }
        
        internal static X509Certificate2 ExportCertificatePublicKey(this X509Certificate2 certificate)
        {
            var publicKeyBytes = certificate.Export(X509ContentType.Cert);
            var signingCertWithoutPrivateKey = new X509Certificate2(publicKeyBytes);
            return signingCertWithoutPrivateKey;
        }

        static string directory = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
        static string pathToCerts = $"{directory}/../../../../Certs/";

        public static string CertPath(string fileName)
            => Path.GetFullPath(Path.Combine(pathToCerts, fileName));
    }
}