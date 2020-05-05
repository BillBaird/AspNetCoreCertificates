using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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
        static void Main(string[] args)
        {
            var serviceProvider = new ServiceCollection()
                .AddCertificateManager()
                .BuildServiceProvider();

            string password = "1234";
            var cc = serviceProvider.GetService<CreateCertificatesClientServerAuth>();
            var iec = serviceProvider.GetService<ImportExportCertificate>();
            
            // Create SB Root Certificate Authority
            var sbCa = cc.NewRootCertificate(
                new DistinguishedName { CommonName = "sbCertificateAuthority", Country = "GB" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                3, "localhost");
            //Console.WriteLine(sbCa.ToShortString());
            //Console.ReadLine();
            //Console.WriteLine(sbCa.InterpretAsString());
            
            // Export SB Root Certificate Authority as PFX
            var rootCertInPfxBytes = iec.ExportRootPfx(password, sbCa);
            var fileName = "sbCertificateAuthority.pfx";
            File.WriteAllBytes(fileName, rootCertInPfxBytes);

            // Create SB Device Registration Service Intermediate Certificate
            var sbDrs = cc.NewIntermediateChainedCertificate(
                new DistinguishedName { CommonName = "sbDeviceRegistrationService", Country = "GB" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                2, "localhost", sbCa);
            //Console.WriteLine(sbDrs.ToShortString());
            //Console.ReadLine();
            //Console.WriteLine(sbDrs.InterpretAsString());
            
            // Export SB Device Registration Service Intermediate Certificate Chain as PFX
            var sbDrsBytes = iec.ExportChainedCertificatePfx(password, sbDrs, sbCa);
            fileName = "sbDeviceRegistrationService.pfx";
            File.WriteAllBytes(fileName, sbDrsBytes);
            Console.WriteLine($"Exported {fileName}");

            // Show the DRS trust chain from the bytes which were exported 
            var certs = new X509Certificate2Collection();
            certs.Import(sbDrsBytes, password, X509KeyStorageFlags.EphemeralKeySet);
            var trustChain = certs.GetTrustChain();
            for (var i = 0; i < trustChain.Count; i++)
                Console.WriteLine(trustChain[i].ToShortString(i * 4));
            
            // Create device certificate
            var testDevice01 = cc.NewDeviceChainedCertificate(
                new DistinguishedName { CommonName = "testdevice01" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                "testdevice01", 
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.NonRepudiation,
                null,
                sbDrs);
            //Console.WriteLine(testDevice01.ToShortString());

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
