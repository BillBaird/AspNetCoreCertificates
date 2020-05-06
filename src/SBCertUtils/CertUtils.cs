using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
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
                sb.Append(", ").Append(EnhancedKeyUsageName(oid));
            return sb.ToString();
        }

        public static string EnhancedKeyUsageName(this Oid oid)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                switch (oid.Value)
                {
                    case "1.3.6.1.5.5.7.3.2":
                        return "TLS Client Authentication";
                    case "1.3.6.1.5.5.7.3.1":
                        return "TLS Server Authentication";
                    case "x": return "x";
                    default: 
                        return oid.Value;
                }
            else
                return oid.FriendlyName;
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

        public static byte[] ExportWithPrivateKey(X509Certificate2 cert, string privateKeyPassword, string pkcs12Password)
        {
            var builder = new Pkcs12Builder();
            var contents = new Pkcs12SafeContents();
            var certBag = contents.AddCertificate(cert);
            var keyBag = contents.AddShroudedKey(cert.GetECDsaPrivateKey(), privateKeyPassword, new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2000));
            builder.AddSafeContentsUnencrypted(contents);

            // OpenSSL requires the file to have a mac, without mac this will run on Windows but not on Linux
            // See hash algorithm comment at the end of
            // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.pkcs12builder.sealwithmac?view=dotnet-plat-ext-3.1
            // SHA1 is used since using SHA2565 here does not work on OSX.
            builder.SealWithMac(pkcs12Password, HashAlgorithmName.SHA1, 2000);
            return builder.Encode();
        }

        /// <summary>
        /// Exports one or more certificates in PKCS12 format representing a chain of trust.  The certificates should start with the leaf
        /// node of the trust tree working their way up to the root CA.
        ///
        /// Note that this implementation is for ECDsa keys.
        /// </summary>
        /// <param name="privateKeyPassword">A password used to shroud the private key of the leaf certificate</param>
        /// <param name="pkcs12Password">A password using to seal the exported PKCS12 bytes</param>
        /// <param name="cert">A set of one or more certificates with the leaf node (the one which for which the private key should be included) given first.</param>
        public static byte[] ExportTrustChainWithPrivateKey(string privateKeyPassword, string pkcs12Password, params X509Certificate2[] cert)
        {
            var builder = new Pkcs12Builder();
            var contents = new Pkcs12SafeContents();
            for (int i = 0; i < cert.Length; i++)
            {
                contents.AddCertificate(cert[i]);
                if (i == 0)
                    contents.AddShroudedKey(cert[i].GetECDsaPrivateKey(), privateKeyPassword, new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2000));
            }
            builder.AddSafeContentsUnencrypted(contents);

            // OpenSSL requires the file to have a mac, without mac this will run on Windows but not on Linux
            // See hash algorithm comment at the end of
            // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.pkcs12builder.sealwithmac?view=dotnet-plat-ext-3.1
            // SHA1 is used since using SHA2565 here does not work on OSX.
            builder.SealWithMac(pkcs12Password, HashAlgorithmName.SHA1, 2000);
            return builder.Encode();
        }
        
    }
}