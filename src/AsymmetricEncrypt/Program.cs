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
           
            var encryptedData = Encrypt(data, rsaPublicKey);
            var decryptedData = Decrypt(encryptedData, rsaPrivateKey);
            if (decryptedData.Length != data.Length || decryptedData[1] != data[1])
                Console.WriteLine("Did not work");
            
            (rsaPublicKey, rsaPrivateKey) = RSAGenerateKeysDeserialized(2048);
            encryptedData = Encrypt(data, rsaPublicKey);
            decryptedData = Decrypt(encryptedData, rsaPrivateKey);
            if (decryptedData.Length != data.Length || decryptedData[1] != data[1])
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

        static (RSAParameters publicKey, RSAParameters privateKey) RSAGenerateKeysDeserialized(int keyLength)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = keyLength;
                //var bytes = rsa.ExportSubjectPublicKeyInfo();
                
                // Export and Import Public Key
                var keyBytes = rsa.ExportRSAPublicKey();
                var keyB64 = Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks);    // Can be hardcoded in app
                Console.WriteLine(keyB64);
                var keyBytesDecoded = Convert.FromBase64String(keyB64);
                var rehydratedRsaPubKey = RSA.Create();
                rehydratedRsaPubKey.ImportRSAPublicKey(keyBytesDecoded, out var pubBytesRead);
                
                Console.WriteLine();
                // Export and Import Private Key
                keyBytes = rsa.ExportRSAPrivateKey();
                keyB64 = Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks);    // Can be hardcoded in app
                Console.WriteLine(keyB64);
                keyBytesDecoded = Convert.FromBase64String(keyB64);
                var rehydratedRsaPrivateKey = RSA.Create();
                rehydratedRsaPrivateKey.ImportRSAPrivateKey(keyBytesDecoded, out var privateBytesRead);
                
                return (
                    publicKey: rehydratedRsaPubKey.ExportParameters(includePrivateParameters: false),
                    privateKey: rehydratedRsaPrivateKey.ExportParameters(includePrivateParameters: true)
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
        
        static (ECParameters publicKey, ECParameters privateKey) ECDsaGenerateKeys(int keyLength)
        {
            using (var ecd = ECDsa.Create())
            {
                ecd.KeySize = keyLength;
                var bytes = ecd.ExportSubjectPublicKeyInfo();
                return (
                    publicKey: ecd.ExportParameters(includePrivateParameters: false),
                    privateKey: ecd.ExportParameters(includePrivateParameters: true)
                );
            }
        }

        /*
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