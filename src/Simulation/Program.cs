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

            // Export SB Device Registration Service Intermediate Certificate Chain as PFX
            var sbDrsBytes = CertUtils.ExportTrustChainWithPrivateKey(password, password, sbDrs, sbCAFromBytes);
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
                null,
                sbDrsFromBytes);
            Console.WriteLine(testDevice01.ToShortString());

            Console.WriteLine("-----------------");
            var sbDeviceBytes = CertUtils.ExportTrustChainWithPrivateKey(password, password, testDevice01, sbDrsFromBytes, sbCAFromBytes);
            certs = new X509Certificate2Collection();
            certs.Import(sbDeviceBytes, password, X509KeyStorageFlags.Exportable);        
            trustChain = certs.GetTrustChain();
            for (var i = 0; i < trustChain.Count; i++)
                Console.WriteLine(trustChain[i].ToShortString(i * 4));
            var testDevice01FromBytes = trustChain.Last();
            SignAndVerify(testDevice01FromBytes, testDevice01);
            
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
            SignAndVerify(deviceFromPfx, testDevice01);
        }

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
