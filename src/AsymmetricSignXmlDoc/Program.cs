using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace AsymmetricSignXmlDoc
{
    class Program
    {
        static void Main(string[] args)
        {
/*
            var (publicKey, privateKey) = RSAGenerateKeys(2048);

            var document = new XmlDocument();
            document.LoadXml("<Root><Author>Meziantou</Author></Root>");

            SignXml(document, privateKey);
            var isValidXmlSignature = VerifyXmlSignature(document, publicKey);
*/
        }
/*

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

        public static void SignXml(XmlDocument xmlDocument, RSAParameters privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);

                var signedXml = new SignedXml(xmlDocument);
                signedXml.SigningKey = rsa;

                // Create a reference to be signed
                var reference = new Reference(""); // "" means entire document, https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.reference.uri
                var env = new XmlDsigEnvelopedSignatureTransform();
                reference.AddTransform(env);

                // Add the reference to the SignedXml object and compute the signature
                signedXml.AddReference(reference);
                signedXml.ComputeSignature();

                // Get the XML representation of the signature and add it to the document
                XmlElement xmlDigitalSignature = signedXml.GetXml();
                xmlDocument.DocumentElement.AppendChild(xmlDocument.ImportNode(xmlDigitalSignature, deep: true));
            }
        }

        public static bool VerifyXmlSignature(XmlDocument xmlDocument, RSAParameters publicKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);

                var signatureElement = xmlDocument.GetElementsByTagName("Signature").OfType<XmlElement>().FirstOrDefault();
                var signedXml = new SignedXml(xmlDocument);
                signedXml.LoadXml(signatureElement);

                return signedXml.CheckSignature(rsa);
            }
        }
*/            
    }
}