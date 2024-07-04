using System.Text;
using encryption.rsa.helpers; // Assuming this is a custom namespace for RSA encryption helpers

// Scenario: RSA Encryption for Company API (Mobile Apps)

// This method generates a public-private RSA key pair.
// The public key will be provided to client applications (iOS and Android)
// for message encryption. The API endpoint will decrypt messages using the private key.
var keys = RsaEncrytion.GenerateKeyPair();

// Convert the private key to PEM format for easy storage (database, etc.)
var privateKeyToPem = RsaEncrytion.ExportKeyToPem(keys.Private);

Console.WriteLine("PEM Format Private Key:\n" + privateKeyToPem); // Improved formatting

// Convert the public key to PEM format for distribution to mobile devices
var publicKeyToPem = RsaEncrytion.ExportKeyToPem(keys.Public);

Console.WriteLine("PEM Format Public Key:\n" + publicKeyToPem); // Improved formatting

// Import the public key from PEM format
var publicKeyFromPem = RsaEncrytion.ImportPublicKeyFromPem(publicKeyToPem);

// Message to be encrypted
var encryptionMessage = "This is my secret message";

// Convert the message to a byte array for encryption
var byteMessage = Encoding.UTF8.GetBytes(encryptionMessage);

// Encrypt the message using the public key
var encryptedMessageBytes = RsaEncrytion.Encrypt(byteMessage, publicKeyFromPem);

// Import the private key from PEM format
var privateKeyFromPem = RsaEncrytion.ImportPrivateKeyFromPem(privateKeyToPem);

// Decrypt the encrypted message using the private key
var decryptedMessages = RsaEncrytion.Decrypt(encryptedMessageBytes, privateKeyFromPem.Private);

// Convert the decrypted message bytes back to a string
var ourMessage = Encoding.UTF8.GetString(decryptedMessages);

Console.WriteLine("Decrypted Message: " + ourMessage);

