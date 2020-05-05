using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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
        
        public static X509Certificate2 ExportCertificatePublicKey(this X509Certificate2 certificate)
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

        public static string ToShortString(this X509Certificate2 cert, int indent = 0)
        {
            var nl = Environment.NewLine;
            var sb = new StringBuilder();
            var keyUsage = (X509KeyUsageExtension)cert.Extensions["2.5.29.15"];
            var enhancedKeyUsage =  (X509EnhancedKeyUsageExtension)cert.Extensions["2.5.29.37"];
            var constraints = (X509BasicConstraintsExtension)cert.Extensions["2.5.29.19"];
            var subjectAltName = cert.Extensions["2.5.29.17"];
            var SAN = (new AsnEncodedData(subjectAltName.Oid, subjectAltName.RawData)).Format(false);
            var spaces = new string(' ', indent);
            sb.Append(spaces).Append("Subject: ").Append(cert.Subject).Append(nl)
                .Append(spaces).Append("AltName: ").Append(SAN).Append(nl)
                .Append(spaces).Append("Issuer: ").Append(cert.Issuer).Append(nl)
                .Append(spaces).Append("HasPrivateKey: ").Append(cert.HasPrivateKey.ToString()).Append(nl)
                .Append(spaces).Append("Valid: ").Append(cert.NotBefore).Append(" to ").Append(cert.NotAfter).Append(nl)
                .Append(spaces).Append("Constraints: CA=").Append(constraints.CertificateAuthority).Append($"{(constraints.HasPathLengthConstraint ? $", PathLength={constraints.PathLengthConstraint}" : null)}").Append(nl)
                .Append(spaces).Append("Usages: ").Append(keyUsage?.KeyUsages.ToString());
            foreach (var oid in enhancedKeyUsage.EnhancedKeyUsages)
                sb.Append(", ").Append(oid.FriendlyName);
            return sb.ToString();
        }

        /// <summary>
        /// Given a X509Certificate2Collection which represents a chain of trust, returns the chain as a list sorted
        /// with the rootCA first, continuing down the chain in parent/child order.
        /// </summary>
        public static List<X509Certificate2> GetTrustChain(this X509Certificate2Collection certs)
        {
            var list = new List<X509Certificate2>(certs.Count);
            foreach (var c in certs)
            {
                if (c.SubjectName.Name.Equals(c.IssuerName.Name))
                    list.Insert(0, c);
                else
                    list.Add(c);
            }

            for (int parentInx = 0; parentInx < list.Count - 1; parentInx++)
            {
                var parent = list[parentInx];
                for (int i = parentInx + 1; i < list.Count; i++)
                {
                    if (list[i].IssuerName.Name.Equals(parent.SubjectName.Name))
                        if (i != parentInx + 1)
                        {
                            list.Insert(parentInx + 1, list[i]);
                            list.RemoveAt(i + 1);
                            break;
                        }
                }
            }

            return list;
        }
        
        public static byte[] SignECC(this X509Certificate2 cert, byte[] data)
        {
            using var ecc = cert.GetECDsaPrivateKey();
            // the hash to sign
            byte[] hash;
            using (var sha256 = SHA256.Create())
            {
                hash = sha256.ComputeHash(data);
            }

            return ecc.SignHash(hash);
        }

        public static bool VerifySignatureECC(this X509Certificate2 cert, byte[] data, byte[] signature)
        {
            using var ecc = cert.GetECDsaPublicKey();
            // the hash to verify
            byte[] hash;
            using (var sha256 = SHA256.Create())
            {
                hash = sha256.ComputeHash(data);
            }
            
            return ecc.VerifyHash(hash, signature);
        }    

    }
}