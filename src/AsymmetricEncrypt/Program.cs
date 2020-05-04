using System;
using System.Security.Cryptography;

namespace AsymetricEncrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            var data = new byte[] { 1, 2, 3 };
            var (rsaPublicKey, rsaPrivateKey) = RSAGenerateKeys(2048);
           
            Console.WriteLine(rsaPublicKey.ToString());
            
            var encryptedData = Encrypt(data, rsaPublicKey);
            var decryptedData = Decrypt(encryptedData, rsaPrivateKey);
            if (decryptedData[1] != data[1])
                Console.WriteLine("Did not work");
        }

        static (RSAParameters publicKey, RSAParameters privateKey) RSAGenerateKeys(int keyLength)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = keyLength;
                return (
                    publicKey: rsa.ExportParameters(includePrivateParameters: false),
                    privateKey: rsa.ExportParameters(includePrivateParameters: true)
                );
            }
        }

        static byte[] Encrypt(byte[] data, RSAParameters publicKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);

                var result = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
                return result;
            }
        }

        static byte[] Decrypt(byte[] data, RSAParameters privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);
                return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
        }
        
        /*
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

        static byte[] Encrypt(byte[] data, ECParameters publicKey)
        {
            using (var ecd = ECDsa.Create())
            {
                ecd.ImportParameters(publicKey);

                var result = ecd.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
                return result;
            }
        }

        static byte[] Decrypt(byte[] data, ECParameters privateKey)
        {
            using (var ecd = ECDsa.Create())
            {
                ecd.ImportParameters(privateKey);
                return ecd.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
        }
        */
        
    }
}