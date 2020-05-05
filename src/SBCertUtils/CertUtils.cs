using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
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
            Console.WriteLine(PrivateKeyDesc(cert));
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

        public static string InterpretAsString(this X509Certificate2 cert, bool verbose = true)
        {
            var s = cert.ToString(verbose);
            s = s.Replace("* (2.5.29.35):", "* X509v3 Authority Key Identifier(2.5.29.35):");
            s = s.Replace("* (2.5.29.17):", "* X509v3 Subject Alt Name(2.5.29.17):");
            if (s.Contains("(2.5.29.15):") && RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var keyUsage = (X509KeyUsageExtension)cert.Extensions["2.5.29.15"];
                s = s.Replace("(2.5.29.15):", $"(2.5.29.15):{Environment.NewLine}  [{keyUsage.KeyUsages.ToString()}]");
            }

            if (cert.HasPrivateKey)
                s = s.Replace($"[Private Key]{Environment.NewLine}", $"[Private Key]{Environment.NewLine}{PrivateKeyDesc(cert)}");
            
            return s;
        }

        private static string PrivateKeyDesc(X509Certificate2 cert)
        {
            if (!cert.HasPrivateKey)
                return null;
            switch (cert.PublicKey.Oid.Value) {
                case RSA:
                    RSA_Label:
                    RSA rsa = cert.GetRSAPrivateKey(); // or cert.GetRSAPublicKey() when need public key
                    return $"  RSA PrivateKey: {rsa}\n  SignatureAlgorithm: {rsa.SignatureAlgorithm}\n  KeyExchangeAlgorithm: {rsa.KeyExchangeAlgorithm}\n  KeySize: {rsa.KeySize}";
                case DSA:
                    DSA dsa = cert.GetDSAPrivateKey(); // or cert.GetDSAPublicKey() when need public key
                    return $"  DSA PrivateKey: {dsa}\n  SignatureAlgorithm: {dsa.SignatureAlgorithm}\n  KeyExchangeAlgorithm: {dsa.KeyExchangeAlgorithm}\n  KeySize: {dsa.KeySize}";
                case ECC:
                    ECDsa ecc = cert.GetECDsaPrivateKey(); // or cert.GetECDsaPublicKey() when need public key
                    if (ecc == null)
                    {
                        Console.WriteLine("ecc was null, will do RSA");
                        goto RSA_Label;
                    }
                    return $"  ECC PrivateKey = {ecc}\n  SignatureAlgorithm: {ecc.SignatureAlgorithm}\n  KeyExchangeAlgorithm: {ecc.KeyExchangeAlgorithm}\n  KeySize: {ecc.KeySize}";
                default:
                    return $"  Unknown PublicKey OID value {cert.PublicKey.Oid.Value} for interpreting Private Key";
            }
        }
    }
}