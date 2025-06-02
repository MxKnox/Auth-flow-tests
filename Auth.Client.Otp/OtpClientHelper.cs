using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Auth.Common;
using Auth.Common.Certificates;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using static System.Net.WebRequestMethods;

namespace Auth.Client.Otp
{
    public class OtpClientHelper
    {
        private readonly HttpClientHandler _httpClientHandler;
        private readonly HttpClient _httpClient;

        private AsymmetricCipherKeyPair _keys;
        private ClientRecord _clientRecord;

        private X509Certificate2? _serverSignedCert;

        public OtpClientHelper()
        {
            // Create a new instance of HttpClient to prevent pollution of cookies and shared resources from DI Factory IHttpClientFactory's single HttpMessageHandler
            var cookieContainer = new CookieContainer();
            _httpClientHandler = new HttpClientHandler() { CookieContainer = cookieContainer};
            _httpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
            _httpClientHandler.SslProtocols = System.Security.Authentication.SslProtocols.Tls13;

            _httpClientHandler.ServerCertificateCustomValidationCallback =
                (HttpRequestMessage, cert, certChain, policyErrors) =>
                {
                    // bypass certificate validation for demo.
                    return true;
                };
            _httpClient = new HttpClient(_httpClientHandler);

            SetupClient();   
        }

        public void SetupClient()
        {
            Console.WriteLine($"CREATING OTP CLIENT HELPER");

            // get new keys for client
            _keys = ClientCertificateHelper.GenerateSigningKeyPair();

            var encodedPubKey = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_keys.Public).GetEncoded();
            var pubKeyHash = Convert.ToBase64String(SHA256.HashData(encodedPubKey));

            // example client
            _clientRecord = new ClientRecord()
            {
                Id = Guid.NewGuid(),
                Host = Dns.GetHostName(),
                Name = "__TEST__NON-INTERACTIVE-CLIENT",
                PhoneNumber = "1234567890",
                Email = "me@acme.com",
                PublicKeyHash = pubKeyHash,
                IsInteractiveClient = false
            };

            Console.WriteLine($"CLIENT ID: {_clientRecord.Id}");
        }


        public async Task Register()
        {
            var registerRequest = new HttpRequestMessage(HttpMethod.Post, "https://localhost:7264/api/non-interactive/register");

            var selfSignedClientCert = ClientCertificateHelper.GetSelfSignedCertificate(_keys, _clientRecord.Id.ToString().ToLowerInvariant());


            _httpClientHandler.ClientCertificates.Clear();
            _httpClientHandler.ClientCertificates.Add(selfSignedClientCert);
            

            var json = JsonSerializer.Serialize(_clientRecord);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            registerRequest.Content = content;

            var response = await _httpClient.SendAsync(registerRequest);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine($"Registration Failed");
            }
        }

        public async Task<bool> TryAuthenticate(string Otp)
        {
            var authenticateRequest = new HttpRequestMessage(HttpMethod.Post, "https://localhost:7264/api/non-interactive/authenticate");

            /// set auth headers
            authenticateRequest.Headers.Add(ClientAuthenticationHeaders.OtpCode, new List<string>() { Otp });
            authenticateRequest.Headers.Add(ClientAuthenticationHeaders.ClientId, new List<string>() { _clientRecord.Id.ToString().ToLowerInvariant() });

            var response = await _httpClient.SendAsync(authenticateRequest);

            if (response.StatusCode != HttpStatusCode.OK)
            {
                // failed to authenticate/validate otp for client
                return false;
            }

            var headerCert = response.Headers.FirstOrDefault(x => x.Key == ClientAuthenticationHeaders.SignedCertificate).Value.First();

            //var responseBody = await response.Content.ReadAsStringAsync();

            var certBytes = Convert.FromBase64String(headerCert);

            //Get Bytes

            ClientCertificateHelper.UpdateClientCert(certBytes, _clientRecord.Id.ToString().ToLowerInvariant());

            Console.WriteLine("Success, server returned a signed key");

            // set the current HttpClient certificates to be the new cert.

            var cert = ClientCertificateHelper.LoadCertificateFromPfx(_clientRecord.Id.ToString().ToLowerInvariant());
            _httpClientHandler.ClientCertificates.Clear();
            _httpClientHandler.ClientCertificates.Add(cert);
            
            return true;
        }



        public async Task ReflectClientInfo()
        {
            var testGet = new HttpRequestMessage(HttpMethod.Get, "https://localhost:7264/api/whoami");
            

            var response = await _httpClient.SendAsync(testGet);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                Console.WriteLine(response.Content.ToString());
                var reflectedClient = await response.Content.ReadFromJsonAsync<ClientRecord>();

                Console.WriteLine("Reflected Client from Auth:");
                Console.WriteLine($"ClientId: {reflectedClient.Id}");
                Console.WriteLine($"Host: {reflectedClient.Host}");
                Console.WriteLine($"Interactive: {reflectedClient.IsInteractiveClient}");
                Console.WriteLine($"{(reflectedClient.Id == _clientRecord.Id ? "MATCHES" : "DOESN'T MATCH")}");


            } else
            {
                Console.WriteLine("Failed to retrieve Client details");
            }

    
        }

    }
}
