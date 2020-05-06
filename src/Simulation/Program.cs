using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertificateManager;
using CertificateManager.Models;
using Microsoft.Extensions.DependencyInjection;
using SBCertUtils;

namespace Simulation
{
    class Program
    {
        private static CreateCertificatesClientServerAuth cc;
        private static ImportExportCertificate iec;
        
        static void Main(string[] args)
        {
            var serviceProvider = new ServiceCollection()
                .AddCertificateManager()
                .BuildServiceProvider();

            string password = "1234";
            cc = serviceProvider.GetService<CreateCertificatesClientServerAuth>();
            iec = serviceProvider.GetService<ImportExportCertificate>();
            
            // Create SB Root Certificate Authority
            var sbCa = cc.NewRootCertificate(
                new DistinguishedName { CommonName = "sbCertificateAuthority", Country = "GB" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                3, "localhost");
            Console.WriteLine(sbCa.ToShortString());
            //Console.ReadLine();
            //Console.WriteLine(sbCa.InterpretAsString());
            SignAndVerify(sbCa);
            
            // Export SB Root Certificate Authority as PFX
            var rootCertInPfxBytes = CertUtils.ExportTrustChainWithPrivateKey(password, password, sbCa);
            var fileName = "sbCertificateAuthority.pfx";
            File.WriteAllBytes(fileName, rootCertInPfxBytes);

            // Load the certificate back from the bytes and verify that it works
            var rootInfo = Pkcs12Info.Decode(rootCertInPfxBytes, out var bytesConsumed, false);
            Console.WriteLine($"Encoded len = {rootCertInPfxBytes.Length}, consumed = {bytesConsumed}");
            Console.WriteLine($"MAC Verified = {rootInfo.VerifyMac(password)}");
            var sbCAFromBytes = new X509Certificate2(rootCertInPfxBytes, password);
            Console.WriteLine(sbCAFromBytes.ToShortString());
            //Console.WriteLine(sbCAFromBytes.InterpretAsString());
            SignAndVerify(sbCAFromBytes, sbCa);

            // Create SB Device Registration Service Intermediate Certificate
            var sbDrs = cc.NewIntermediateChainedCertificate(
                new DistinguishedName { CommonName = "sbDeviceRegistrationService", Country = "GB" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                2, "localhost", sbCa);
            //Console.WriteLine(sbDrs.ToShortString());
            //Console.ReadLine();
            //Console.WriteLine(sbDrs.InterpretAsString());

            var sbDrsBytes = CertUtils.ExportTrustChainWithPrivateKey(password, password, sbDrs, sbCAFromBytes);
            
            // Export SB Device Registration Service Intermediate Certificate Chain as PFX
            //var sbDrsBytes = iec.ExportChainedCertificatePfx(password, sbDrs, sbCa);
            fileName = "sbDeviceRegistrationService.pfx";
            File.WriteAllBytes(fileName, sbDrsBytes);
            Console.WriteLine($"Exported {fileName}");

            // Show the DRS trust chain from the bytes which were exported 
            var certs = new X509Certificate2Collection();
            certs.Import(sbDrsBytes, password, X509KeyStorageFlags.Exportable);
            var trustChain = certs.GetTrustChain();
            for (var i = 0; i < trustChain.Count; i++)
                Console.WriteLine(trustChain[i].ToShortString(i * 4));
            var sbDrsFromBytes = trustChain.Last();
            
            // Create device certificate
            var testDevice01 = cc.NewDeviceChainedCertificate(
                new DistinguishedName { CommonName = "testdevice01" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                "testdevice01", 
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.NonRepudiation,
                new OidCollection {
                    new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                    new Oid("1.3.6.1.5.5.7.3.1")  // TLS Server auth
                },
                sbDrsFromBytes);
            Console.WriteLine(testDevice01.ToShortString());

            Console.WriteLine("-----------------");
            var sbDeviceBytes = iec.ExportChainedCertificatePfx(password, testDevice01, sbDrs, certs);
            certs = new X509Certificate2Collection();
            certs.Import(sbDeviceBytes, password, X509KeyStorageFlags.EphemeralKeySet);        
            trustChain = certs.GetTrustChain();
            for (var i = 0; i < trustChain.Count; i++)
                Console.WriteLine(trustChain[i].ToShortString(i * 4));

            var testDevice01PublicKey = iec.ExportCertificatePublicKey(testDevice01);
            var testDevice01PublicKeyBytes = testDevice01PublicKey.Export(X509ContentType.Cert);
            
            // Sign with device private key
            var msg = new byte[] {1, 2, 3};
            var sig = testDevice01.SignECC(msg);
            Console.WriteLine($"Data:{ByteArrayToString(msg)}, Signature:{ByteArrayToString(sig)}");
            
            // Verify the signature using only a depersisted form of the devices public key.  This is what would be
            // stored on the device record (the private key is only in the device) and is how we verify the message is
            // from the device.
            var depersistedTestDevice01PubKey = new X509Certificate2(testDevice01PublicKeyBytes);
            //Console.WriteLine(depersistedTestDevice01PubKey.ToShortString());
            Console.WriteLine($"Verified = {depersistedTestDevice01PubKey.VerifySignatureECC(msg, sig)}");
            
            // Get device from chain
            X509Certificate2 deviceFromPfx = null;
            foreach (var c in certs)
            {
                if ("CN=testdevice01".Equals(c.SubjectName.Name))
                {
                    deviceFromPfx = c;
                    break;
                }
            }
            Console.WriteLine(deviceFromPfx.ToShortString());
            sig = deviceFromPfx.SignECC(msg);
            Console.WriteLine($"Data:{ByteArrayToString(msg)}, Signature:{ByteArrayToString(sig)}");
            Console.WriteLine($"Verified = {depersistedTestDevice01PubKey.VerifySignatureECC(msg, sig)}");
        }

        /*
        public static X509Certificate2 CreateCertificateWithPrivateKey(
            X509Certificate2 certificate, 
            AsymmetricAlgorithm privateKey, 
            string password = null)
        {
            var builder = new Pkcs12Builder();
            var contents = new Pkcs12SafeContents();
            var certBag = contents.AddCertificate(certificate);
            var keyBag = contents.AddKeyUnencrypted(privateKey);
            builder.AddSafeContentsUnencrypted(contents);

            // OpenSSL requires the file to have a mac, without mac this will run on Windows but not on Linux
            builder.SealWithMac(password, HashAlgorithmName.SHA256, 1);
            var pkcs12bytes = builder.Encode();

            if (string.IsNullOrEmpty(password))
            {
                var certificateOut = new X509Certificate2(pkcs12bytes);
                return certificateOut;
            }
            else
            {
                var certificateOut = new X509Certificate2(pkcs12bytes, password);
                return certificateOut;
            }
        }
        */

        static bool SignAndVerify(X509Certificate2 cert)
        {
            return SignAndVerify(cert, iec.ExportCertificatePublicKey(cert).Export(X509ContentType.Cert));
        }

        static bool SignAndVerify(X509Certificate2 signingCert, X509Certificate2 verifyingCert)
        {
            return SignAndVerify(signingCert, iec.ExportCertificatePublicKey(verifyingCert).Export(X509ContentType.Cert));
        }
        
        static bool SignAndVerify(X509Certificate2 cert, byte[] publicKeyBytes)
        {
            // Sign with device private key
            var msg = new byte[] {1, 2, 3};
            var sig = cert.SignECC(msg);
            Console.WriteLine($"Data:{ByteArrayToString(msg)}, Signature:{ByteArrayToString(sig)}");
            
            // Verify the signature using only a depersisted form of the devices public key.  This is what would be
            // stored on the device record (the private key is only in the device) and is how we verify the message is
            // from the device.
            var depersistedTestDevice01PubKey = new X509Certificate2(publicKeyBytes);
            //Console.WriteLine(depersistedTestDevice01PubKey.ToShortString());
            var verified = depersistedTestDevice01PubKey.VerifySignatureECC(msg, sig);
            Console.WriteLine($"Signature Verified = {verified}");
            return verified;
        }
        
        
        static string ByteArrayToString(byte[] byteArray)
        {
            var hex = new StringBuilder(byteArray.Length * 2);
            foreach (var b in byteArray)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}
