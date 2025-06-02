using Auth.Common.Certificates;
using Auth.Common;
using Microsoft.AspNetCore.Http;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.Asn1;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using Org.BouncyCastle.Pkcs;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Mvc.Routing;
using System.IO.Pipelines;

namespace Auth.Server.Mtls
{
    public static class ServerCertHelper
    {
        public const string CERT_NAME = "server";


        /// <summary>
        /// Loads server cert if one exists, and creates a self signed cert if not
        /// </summary>
        /// <returns></returns>
        public static X509Certificate2 GetServerCert()
        {

            var cert = ClientCertificateHelper.LoadCertificateFromPfx(CERT_NAME);
            if (cert == null)
            {
                //create a new cert and write it to disk to keep a consistent cert for duration of demo.
                var keys = ClientCertificateHelper.GenerateSigningKeyPair();

                var selfSignedCert = ClientCertificateHelper.GetSelfSignedCertificate(keys, CERT_NAME, DateTime.UtcNow.AddDays(365));
                //ClientCertificateHelper.WriteCertToDisk(selfSignedCert, CERT_NAME, "");

                // try load from file to ensure it actually writes
                cert = ClientCertificateHelper.LoadCertificateFromPfx(CERT_NAME);

                if (cert == null)
                    throw new Exception("Unabled to load cert");
            }

            return cert;
        }

        public static Pkcs12Store GetServerPkcs12Store()
        {
            var store = new Pkcs12StoreBuilder().Build();
            using (var fs = new FileStream(ClientCertificateHelper.GetCertPath(CERT_NAME), FileMode.Open, FileAccess.Read))
            {
                store.Load(fs, string.Empty.ToCharArray());
            }

            return store;
        }

        /// sign with BouncyCastle
        public static X509Certificate GenerateCertificate(
            AsymmetricKeyParameter publicKey,
            Guid ClientId,
            DateTime NotAfter
        )
        {            
            var signingCert = GetServerCert();
            var subjectName = $"CN={ClientId.ToString().ToLowerInvariant()}";

            // Convert signing certificate to BouncyCastle format
            var bcSigningCert = new X509CertificateParser().ReadCertificate(signingCert.RawData);

            var store = GetServerPkcs12Store();


            var alias = CERT_NAME;
            if (!store.ContainsAlias(alias))
            {
                alias = store.Aliases.First();
            }

            var certEntry = store.GetCertificate(alias);
            var keyEntry = store.GetKey(alias);

            var certGen = new X509V3CertificateGenerator();

            // Set certificate properties
            certGen.SetSerialNumber(BigInteger.ValueOf(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
            certGen.SetIssuerDN(bcSigningCert.SubjectDN);
            certGen.SetSubjectDN(new X509Name(subjectName));
            certGen.SetNotBefore(DateTime.UtcNow.Date);
            certGen.SetNotAfter(NotAfter);
            certGen.SetPublicKey(publicKey);

            // Add basic extensions
            certGen.AddExtension(
                X509Extensions.SubjectKeyIdentifier, 
                false, 
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(publicKey)
            );

            certGen.AddExtension(
                X509Extensions.AuthorityKeyIdentifier, 
                false, 
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(bcSigningCert)
            );

            certGen.AddExtension(
                X509Extensions.BasicConstraints, 
                true, 
                new BasicConstraints(false)
            );

            certGen.AddExtension(
                X509Extensions.KeyUsage, 
                true,
                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment)
            );

            // Generate certificate with SHA256withECDSA
            

            var sigGen = new Asn1SignatureFactory("SHA256withECDSA", keyEntry.Key);
            var certificate = certGen.Generate(sigGen);
            

            return certificate;
        }

        /// <summary>
        /// sign with .net standard System.Security namespace
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="ClientId"></param>
        /// <param name="NotAfter"></param>
        /// <returns></returns>
        public static X509Certificate2 GenerateCertificate_Standard(
         ECDsa publicKey,
         Guid clientId,
         DateTimeOffset notAfter
     )
        {
            var signingCert = GetServerCert();
            var subjectName = $"CN={clientId.ToString().ToLowerInvariant()}";

            var certRequest = new CertificateRequest(
                subjectName,
                publicKey,
                HashAlgorithmName.SHA256);

            certRequest.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(certificateAuthority: false, false, 0, critical: true));

            certRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement, critical: true)
                );

            var csrBytes = certRequest.CreateSigningRequest();

            // Generate random Serial number for cert instead of looking them up
            var serial = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(serial);
            }

            var signedCert = certRequest.Create(signingCert, notBefore: DateTimeOffset.UtcNow, notAfter, serial);

            return signedCert;
        }


        public static bool IsCertValidForRegistration(this ClientRecord client, X509Certificate certificate )
        {
            // bad DN
            var dnTestValue = new X509Name($"CN={client.Id.ToString().ToLowerInvariant()}");
            if (!certificate.SubjectDN.Equivalent(dnTestValue))
            {
                return false;
            }

            // expired
            if (certificate.NotAfter < DateTime.UtcNow) return false;


            var pubKeyHash = Convert.ToBase64String(SHA256.HashData(certificate.SubjectPublicKeyInfo.GetDerEncoded()));
            return client.PublicKeyHash == pubKeyHash;
        }
    }
}
