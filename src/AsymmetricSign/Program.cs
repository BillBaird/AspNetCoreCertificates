using System;
using System.Security.Cryptography;

namespace AsymmetricSign
{
    class Program
    {
        static void Main(string[] args)
        {
            var (publicKey, privateKey) = RSAGenerateKeys(2048);

            var data = new byte[] { 1, 2, 3 };
            var signedData = Sign(data, privateKey);
            var isValid = VerifySignature(data, signedData, publicKey);
            if (!isValid)
                Console.WriteLine("RSA Signature Failed");

            var (ecdPublicKey, ecdPrivateKey) = ECDsaGenerateKeys(256);
            
            signedData = Sign(data, ecdPrivateKey);
            isValid = VerifySignature(data, signedData, ecdPublicKey);
            if (!isValid)
                Console.WriteLine("ECDsa Signature Failed");
        }

        static (RSAParameters publicKey, RSAParameters privateKey) RSAGenerateKeys(int keyLength)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = keyLength;
                return (
                    publicKey: rsa.ExportParameters(includePrivateParameters: false),
                    privateKey: rsa.ExportParameters(includePrivateParameters: true));
            }
        }

        static byte[] Sign(byte[] data, RSAParameters privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);

                // the hash to sign
                byte[] hash;
                using (var sha256 = SHA256.Create())
                {
                    hash = sha256.ComputeHash(data);
                }

                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
                rsaFormatter.SetHashAlgorithm("SHA256");
                return rsaFormatter.CreateSignature(hash);
            }
        }

        private static bool VerifySignature(byte[] data, byte[] signature, RSAParameters publicKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);

                // the hash to sign
                byte[] hash;
                using (var sha256 = SHA256.Create())
                {
                    hash = sha256.ComputeHash(data);
                }

                var rsaFormatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaFormatter.SetHashAlgorithm("SHA256");
                return rsaFormatter.VerifySignature(hash, signature);
            }
        }    
        
        static (ECParameters publicKey, ECParameters privateKey) ECDsaGenerateKeys(int keyLength)
        {
            using (var ecd = ECDsa.Create())
            {
                ecd.KeySize = keyLength;
                return (
                    publicKey: ecd.ExportParameters(includePrivateParameters: false),
                    privateKey: ecd.ExportParameters(includePrivateParameters: true)
                );
            }
        }

        static byte[] Sign(byte[] data, ECParameters privateKey)
        {
            using (var ecc = ECDsa.Create())
            {
                ecc.ImportParameters(privateKey);

                // the hash to sign
                byte[] hash;
                using (var sha256 = SHA256.Create())
                {
                    hash = sha256.ComputeHash(data);
                }

                return ecc.SignHash(hash);
            }
        }
 
        private static bool VerifySignature(byte[] data, byte[] signature, ECParameters publicKey)
        {
            using (var ecc = ECDsa.Create())
            {
                ecc.ImportParameters(publicKey);

                // the hash to sign
                byte[] hash;
                using (var sha256 = SHA256.Create())
                {
                    hash = sha256.ComputeHash(data);
                }

                return ecc.VerifyHash(hash, signature);
            }
        }    
    }
}