using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
            Console.WriteLine(sbCa.ToShortString());
            Console.ReadLine();
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
            sbCa.ToShortString();
            Console.WriteLine(sbDrs.ToShortString());
            Console.ReadLine();
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
        }
    }
}
