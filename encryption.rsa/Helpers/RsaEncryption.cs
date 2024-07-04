using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using System.IO;

namespace encryption.rsa.helpers
{
    public class RsaEncrytion
    {
        private const int KeySize = 2048;

        public static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), KeySize);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        public static string ExportKeyToPem(AsymmetricKeyParameter key)
        {
            using (StringWriter stringWriter = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(stringWriter);
                pemWriter.WriteObject(key);
                pemWriter.Writer.Flush();
                return stringWriter.ToString();
            }
        }

        public static AsymmetricKeyParameter ImportPublicKeyFromPem(string pem)
        {
            using (StringReader stringReader = new StringReader(pem))
            {
                PemReader pemReader = new PemReader(stringReader);
                return (AsymmetricKeyParameter)pemReader.ReadObject();
            }
        }

        public static AsymmetricCipherKeyPair ImportPrivateKeyFromPem(string pem)
        {
            using (StringReader stringReader = new StringReader(pem))
            {
                PemReader pemReader = new PemReader(stringReader);
                return (AsymmetricCipherKeyPair)pemReader.ReadObject();
            }
        }

        public static byte[] Encrypt(byte[] data, AsymmetricKeyParameter publicKey)
        {
            var encryptEngine = new OaepEncoding(
                new RsaEngine(),
                new Sha256Digest(),
                new Sha256Digest(),
                null // MGF1 Parameters, typically left null for default
            );
            encryptEngine.Init(true, publicKey);
            return encryptEngine.ProcessBlock(data, 0, data.Length);
        }

        public static byte[] Decrypt(byte[] data, AsymmetricKeyParameter privateKey)
        {
            var decryptEngine = new OaepEncoding(
                new RsaEngine(),
                new Sha256Digest(),
                new Sha256Digest(),
                null // MGF1 Parameters, typically left null for default
            );
            decryptEngine.Init(false, privateKey);
            return decryptEngine.ProcessBlock(data, 0, data.Length);
        }

        public static void SaveKeyToDatabase(string connectionString, string publicKey, string privateKey)
        {
            throw new Exception("You need to integration database");
        }

        public static void LoadKeyFromDatabase(string connectionString, int keyId)
        {
            throw new Exception("You need to integration database");
        }
    }
}