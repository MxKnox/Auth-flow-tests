using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Common.Certificates
{
    public class ClientCertificateHelper
    {
        private static string CERT_DIR => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certs");
        public static string GetCertPath(string certName)
        {
            var certPath = new DirectoryInfo(CERT_DIR);
            if (!certPath.Exists)
            {
                certPath.Create();
            }

            return Path.Combine(CERT_DIR, $"{certName}.pfx");
        }
        /// <summary>
        /// Generate key pair for certificate - using ecdh for demo, prod should use the ISM preffered PQC algorithm - ML-KEM-1024 (768 length will not be supported past 2030)
        /// </summary>
        public static AsymmetricCipherKeyPair GenerateSigningKeyPair()
        {
            var keyPairGenerator = new ECKeyPairGenerator();
            // ASD preferred curve is P-384 (ISM-0475, ISM-1736, ISM-1764)
            var keyGenParams = new ECKeyGenerationParameters(
                ECNamedCurveTable.GetOid("P-384"),
                new Org.BouncyCastle.Security.SecureRandom()
            );
            keyPairGenerator.Init(keyGenParams);

            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

            return keyPair;   
        }

        public static Pkcs12Store GetCertificateStoreFromPfx(string subjectName)
        {
            var store = new Pkcs12StoreBuilder().Build();
            using var fs = new FileStream(GetCertPath(subjectName), FileMode.Open, FileAccess.Read);
            store.Load(fs, string.Empty.ToCharArray());

            return store;
        }

        public static void WriteStoreToPfx(Pkcs12Store store, string subjectName)
        {
            var fp = GetCertPath(subjectName);
            var fileInfo = new FileInfo(fp);
            if (fileInfo.Exists)
            {
                // delete original file to try help the cert swap be picked up faster.
                fileInfo.Delete();
            }

            using (var fs = new FileStream(fp, FileMode.OpenOrCreate, FileAccess.Write))
            {
                store.Save(fs, string.Empty.ToCharArray(), new SecureRandom());
            }

            // for dev purposes also write out the cer file
            var cert = store.GetCertificate(subjectName).Certificate;
            var pemFileName = Path.Combine(CERT_DIR, $"{subjectName}_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}.der");
            var der = cert.GetEncoded();
            using (var pemCertStream = new FileStream(pemFileName, FileMode.OpenOrCreate, FileAccess.Write))
            {
                pemCertStream.Write(der);
            }
        }

        public static X509Certificate2 GetSelfSignedCertificate(AsymmetricCipherKeyPair keys, string subjectName, DateTime? notAfter = null)
        {
            // if there is a copy saved for this subjectName and it's not expired try load that first.
            var currentCert = LoadCertificateFromPfx(subjectName);
            if (currentCert is not null && currentCert.NotAfter > DateTime.UtcNow) 
            {
                // cert is still valid, try use it isnted of generating a new cert.
                return currentCert;
            }

            // Create certificate generator
            var certGenerator = new X509V3CertificateGenerator();

            // Set certificate properties
            var serialNumber = BigInteger.ProbablePrime(120, new Random());
            certGenerator.SetSerialNumber(serialNumber);

            var subjectDN = new X509Name($"CN={subjectName}");
            certGenerator.SetSubjectDN(subjectDN);
            certGenerator.SetIssuerDN(subjectDN); // Self-signed, so issuer = subject
            
            certGenerator.SetNotBefore(DateTime.UtcNow);
            certGenerator.SetNotAfter(notAfter ?? DateTime.UtcNow.AddDays(1));

            certGenerator.SetPublicKey(keys.Public);

            // Add basic extensions
            certGenerator.AddExtension(
                X509Extensions.BasicConstraints,
                false,
                new BasicConstraints(true)
            );

            certGenerator.AddExtension(
                X509Extensions.KeyUsage,
                false,
                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyAgreement | KeyUsage.KeyCertSign)
            );

            // Self-sign the certificate using SHA256withECDSA
            var signatureFactory = new Asn1SignatureFactory("SHA256withECDSA", keys.Private, new SecureRandom());
            var certificate = certGenerator.Generate(signatureFactory);

            var store = new Pkcs12StoreBuilder().Build();
            var certEntry = new X509CertificateEntry(certificate);

            store.SetCertificateEntry(subjectName, certEntry);
            store.SetKeyEntry(subjectName, new AsymmetricKeyEntry(keys.Private), new[] { certEntry });


            WriteStoreToPfx(store, subjectName);
            //// Convert to .NET X509Certificate2
            //var x509Cert = new X509Certificate2(certificate.GetEncoded(), string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            //// Create a new X509Certificate2 with the private key
            //var ecdsaPrivateKey = (ECPrivateKeyParameters)keys.Private;
            //var ecdsaPublicKey = (ECPublicKeyParameters)keys.Public;

            //// Convert BouncyCastle private key to .NET ECDsa
            //var ecdsa = ECDsa.Create();
            //var ecParams = new ECParameters
            //{
            //    Curve = ECCurve.NamedCurves.nistP384,
            //    D = ecdsaPrivateKey.D.ToByteArrayUnsigned(),
            //    Q = new ECPoint
            //    {
            //        X = ecdsaPublicKey.Q.AffineXCoord.GetEncoded(),
            //        Y = ecdsaPublicKey.Q.AffineYCoord.GetEncoded()
            //    }
            //};
            //ecdsa.ImportParameters(ecParams);

            //// Create final certificate with private key
            //var certWithPrivateKey = x509Cert.CopyWithPrivateKey(ecdsa);

            //// hack to make windows use it... SChannel wont use in memory only certificates.
            //WriteCertToDisk(certWithPrivateKey, subjectName);
            var fromDisk = LoadCertificateFromPfx(subjectName);

            return fromDisk;
        }

        public static void UpdateClientCert(byte[] signedCertBytes, string subjectName)
        {
            // load current pkcs12 store
            var store = GetCertificateStoreFromPfx(subjectName);
            var key = store.GetKey(subjectName);

            var cert = new Org.BouncyCastle.X509.X509Certificate(signedCertBytes);

            var certEntry = new X509CertificateEntry(cert);

            var newStore = new Pkcs12StoreBuilder().Build();
            newStore.SetCertificateEntry(subjectName, certEntry);
            newStore.SetKeyEntry(subjectName, key, new[]{ certEntry});


            WriteStoreToPfx(newStore, subjectName);
        }

        public static X509Certificate2? LoadCertificateFromPfx(string subjectName)
        {
            var certPath = GetCertPath(subjectName);
            if (!File.Exists(certPath))
            {
                Console.WriteLine($"Certificate file not found: {certPath}, returning null");
                return null;
            }
                
            var certBytes = File.ReadAllBytes(certPath);

            var cert = new X509Certificate2(certBytes, string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            Console.WriteLine($"Loaded certificate(s) from {certPath}");

            return cert;
        }

    }
}
