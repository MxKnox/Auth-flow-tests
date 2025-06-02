using Auth.Common;
using Auth.Common.Certificates;
using Auth.Common.Oidc;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Web;

namespace Auth.Client.Oidc
{
    public class InteractiveClientRegistrationHelper: IDisposable
    {
        private readonly HttpClientHandler _httpClientHandler;
        private readonly HttpClient _httpClient;


        private AsymmetricCipherKeyPair _keys;
        private ClientRecord _clientRecord;

        private TokenResponse _tokenResponse;

        private X509Certificate2? _serverSignedCert;

        public InteractiveClientRegistrationHelper()
        {
            // Create a new instance of HttpClient to prevent pollution of cookies and shared resources from DI Factory IHttpClientFactory's single HttpMessageHandler
            var cookieContainer = new CookieContainer();
            _httpClientHandler = new HttpClientHandler() { CookieContainer = cookieContainer };
            _httpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
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
            Console.WriteLine($"CREATING OIDC CLIENT HELPER");

            // get new keys for client
            _keys = ClientCertificateHelper.GenerateSigningKeyPair();

            var encodedPubKey = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_keys.Public).GetEncoded();
            var pubKeyHash = Convert.ToBase64String(SHA256.HashData(encodedPubKey));

            // example client
            _clientRecord = new ClientRecord()
            {
                Id = Guid.NewGuid(),
                Host = Dns.GetHostName(),
                Name = "__TEST__INTERACTIVE-CLIENT",
                PhoneNumber = "1234567890",
                Email = "me@acme.com",
                PublicKeyHash = pubKeyHash,
                IsInteractiveClient = true
            };

            Console.WriteLine($"CLIENT ID: {_clientRecord.Id}");
        }


        public async Task RegisterClient(string serverUrl)
        {
            // hit the /interactive/register endpoint and capture the Authority information provided 
            var registerEndpoint = new Uri(new Uri(serverUrl), "api/interactive/register");
            var clientJson = JsonSerializer.Serialize(_clientRecord);
            var content = new StringContent(clientJson, Encoding.UTF8, "application/json");

            var selfSignedClientCert = ClientCertificateHelper.GetSelfSignedCertificate(_keys, _clientRecord.Id.ToString().ToLowerInvariant());
            _httpClientHandler.ClientCertificates.Clear();
            _httpClientHandler.ClientCertificates.Add(selfSignedClientCert);

            var unAuthenticatedResponse = await _httpClient.PostAsync(registerEndpoint, content);

            if (unAuthenticatedResponse.StatusCode != HttpStatusCode.Unauthorized && unAuthenticatedResponse.StatusCode != HttpStatusCode.Forbidden)
            {
                // this shouldn't happen in the demo context where there is no publicised authority without failing to authenticate first.
                Console.WriteLine("$client authenticated when it wasn't expected to...");
            }

            // get authority, audience and client id from returned headers
            var authorityValues = unAuthenticatedResponse.Headers.FirstOrDefault(h => h.Key == OidcAuthenticationHeaders.Authority).Value;
            if (authorityValues.Count() != 1)
            {
                throw new Exception($"Invalid number of Authorities returned, expected exactly 1, returned {authorityValues.Count()}");
            }

            //var audienceValues = unAuthenticatedResponse.Headers.FirstOrDefault(h => h.Key == OidcAuthenticationHeaders.Audience).Value;
            //// while multiple audiences are technically allowed, only 1 server is used in this implementation
            //if (audienceValues.Count() != 1)
            //{
            //    throw new Exception($"Invalid number of Audiences returned, expected exactly 1, returned {audienceValues.Count()}");
            //}

            var clientIdValues = unAuthenticatedResponse.Headers.FirstOrDefault(h => h.Key == OidcAuthenticationHeaders.ClientId).Value;
            if (clientIdValues.Count() != 1)
            {
                throw new Exception($"Invalid number of ClientIds returned, expected exactly 1, returned {clientIdValues.Count()}");
            }

            var oidcOptions = new OidcOptions()
            {
                Authority = authorityValues.First(),
                ClientId = clientIdValues.First(),
            };

            var tokens = await AuthFlowWithPkceAsync(oidcOptions);

            var at = tokens.AccessToken;
            AuthenticationHeaderValue authHeader = new AuthenticationHeaderValue("Bearer", tokens.IdToken);
            _httpClient.DefaultRequestHeaders.Authorization = authHeader;

            //_httpClient.DefaultRequestHeaders.Add("Authorization", tokens.AccessToken);


            var response = await _httpClient.PostAsync(registerEndpoint, content);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                // Failure, reset.
                Console.WriteLine($"Failed to register");
                return;
            }

            var responseBody = await response.Content.ReadAsStringAsync();

            var cert = response.Headers.FirstOrDefault(x => x.Key == ClientAuthenticationHeaders.SignedCertificate).Value.First();
            var certBytes = Convert.FromBase64String(cert);

            var signedCert = new X509Certificate2(certBytes, "", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            _serverSignedCert = signedCert;

            ClientCertificateHelper.UpdateClientCert(certBytes, _clientRecord.Id.ToString().ToLowerInvariant());

            _httpClientHandler.ClientCertificates.Clear();


            Console.WriteLine("Success, server returned a signed key");

            var reloadedCert = ClientCertificateHelper.LoadCertificateFromPfx(_clientRecord.Id.ToString().ToLowerInvariant());
            _httpClientHandler.ClientCertificates.Add(reloadedCert);

            

            ReflectClientInfo();
        }


        /// <summary>
        /// Implements 
        /// </summary>
        public async Task<TokenResponse> AuthFlowWithPkceAsync(OidcOptions options) 
        {
            // Step 1: Discover OIDC endpoints
            var discoveryDocument = await DiscoverEndpoints(options);

            // Step 2: Generate PKCE parameters and state
            var (codeVerifier, codeChallenge) = GeneratePkceParameters();
            var state = Guid.NewGuid().ToString("N");

            // Step 3: Build authorization URL
            var authUrl = BuildAuthorizationUrl(options, discoveryDocument.AuthorizationEndpoint, codeChallenge, state);

            // Step 4: Start local listener and open browser
            var authorizationCode = await GetAuthorizationCode(authUrl, state);

            // Step 5: Exchange authorization code for tokens
            var tokenResponse = await ExchangeCodeForTokens(
                options,
                discoveryDocument.TokenEndpoint,
                authorizationCode,
                codeVerifier);

            // Step 6: Output the token
            Console.WriteLine("\n=== TOKEN RESPONSE ===");
            Console.WriteLine($"Access Token: {tokenResponse.AccessToken}");
            Console.WriteLine($"Token Type: {tokenResponse.TokenType}");
            Console.WriteLine($"Expires In: {tokenResponse.ExpiresIn} seconds");

            if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
            {
                Console.WriteLine($"Refresh Token: {tokenResponse.RefreshToken}");
            }

            if (!string.IsNullOrEmpty(tokenResponse.IdToken))
            {
                Console.WriteLine($"ID Token: {tokenResponse.IdToken}");
            }

            return tokenResponse;
        }

        public async Task<DiscoveryDocument> DiscoverEndpoints(OidcOptions options)
        {
            Console.WriteLine("Discovering OIDC endpoints...");

            var discoveryUrl = $"{options.Authority}/.well-known/openid-configuration";
            var response = await _httpClient.GetStringAsync(discoveryUrl);

            var doc = JsonSerializer.Deserialize<DiscoveryDocument>(response, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
            });

            Console.WriteLine($"Authorization Endpoint: {doc.AuthorizationEndpoint}");
            Console.WriteLine($"Token Endpoint: {doc.TokenEndpoint}");

            return doc;
        }

        // AUTH FLOW WITH PKCE RELATED METHODS
        /// <summary>
        /// Generates the codeVerifier and codeChallenge for S256 challenge method.
        /// </summary>
        /// <returns></returns>
        public static (string codeVerifier, string codeChallenge) GeneratePkceParameters()
        {
            // Generate code verifier (43-128 characters)

            var bytes = new byte[64]; //(128 chars) => 2 b64 chars per byte
            RandomNumberGenerator.Fill(bytes);
            var codeVerifier = Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            // Generate code challenge - MUST USE S256 as per RFC 7636 
            var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
            var codeChallenge = Convert.ToBase64String(challengeBytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            return (codeVerifier, codeChallenge);
        }

        public string BuildAuthorizationUrl(OidcOptions options, string authorizationEndpoint, string codeChallenge, string state)
        {
            var queryParams = new Dictionary<string, string>
            {
                {"client_id", options.ClientId},
                {"redirect_uri", options.RedirectUri}, //TODO: Make this a fixed URL that directly opens the application
                {"response_type", "code"},
                {"scope", "openid profile email"},
                {"code_challenge", codeChallenge},
                {"code_challenge_method", "S256"}, // Hard code S256 to prevent "plain" from being used.
                {"state", state},
                {"audience", options.ClientId }
            };

            var queryString = string.Join("&",
                queryParams.Select(kvp => $"{kvp.Key}={HttpUtility.UrlEncode(kvp.Value)}"));

            return $"{authorizationEndpoint}?{queryString}";
        }

        public static async Task<string> GetAuthorizationCode(string authUrl, string expectedState)
        {
            Console.WriteLine("\nStarting authorization flow...");
            Console.WriteLine("Opening browser for authentication...");

            // Start local HTTP listener
            var listener = new System.Net.HttpListener();
            listener.Prefixes.Add("http://localhost:5000/");
            listener.Start();

            // Open browser
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = authUrl,
                    UseShellExecute = true
                });
            }
            catch
            {
                Console.WriteLine($"Please manually open this URL in your browser:");
                Console.WriteLine(authUrl);
            }

            Console.WriteLine("Waiting for authorization response...");

            // Wait for callback
            var context = await listener.GetContextAsync();
            var request = context.Request;
            var response = context.Response;

            // Send response to browser
            string responseString = "<html><body><h1>Authorization received!</h1><p>You can close this window.</p></body></html>";
            byte[] buffer = Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            response.OutputStream.Close();
            listener.Stop();

            // Extract authorization code
            var query = HttpUtility.ParseQueryString(request.Url.Query);
            var code = query["code"];
            var error = query["error"];
            var state = query["state"];

            if (!string.IsNullOrEmpty(error))
            {
                throw new Exception($"Authorization error: {error} - {query["error_description"]}");
            }

            if (string.IsNullOrEmpty(code))
            {
                throw new Exception("No authorization code received");
            }

            if (string.IsNullOrEmpty(state) || state != expectedState)
            {
                throw new Exception("Expected State not received");
            }

            Console.WriteLine("Authorization code received successfully!");
            return code;
        }

        public async Task<TokenResponse> ExchangeCodeForTokens(
            OidcOptions options,
            string tokenEndpoint,
            string authorizationCode,
            string codeVerifier)
        {
            Console.WriteLine("Exchanging authorization code for tokens...");

            var tokenRequest = new Dictionary<string, string>
            {
                {"grant_type", "authorization_code"},
                {"client_id", options.ClientId},
                {"code", authorizationCode},
                {"redirect_uri", options.RedirectUri},
                {"code_verifier", codeVerifier }
            };

            var content = new FormUrlEncodedContent(tokenRequest);

            // origin required for SPAs in MS Entra using PKCE, Add it to ensure entra works as an idp
            _httpClient.DefaultRequestHeaders.Add("Origin", options.RedirectUri);

            var response = await _httpClient.PostAsync(tokenEndpoint, content);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"Token exchange failed: {response.StatusCode} - {responseContent}");
            }

            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
            });

            Console.WriteLine("Tokens received successfully!");
            return tokenResponse;
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
            _httpClientHandler?.Dispose();
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


            }
            else
            {
                Console.WriteLine("Failed to retrieve Client details");
            }


        }
    }
}
