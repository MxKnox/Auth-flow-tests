using Auth.Common.Oidc;
using Auth.Server.Mtls;
using Auth.Common;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.X509;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Pkix;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;

namespace Auth.Server
{
    public static class Extensions
    {

        public static void ConfigureDemoServices(this WebApplicationBuilder builder)
        {
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.ConfigureHttpsDefaults(httpsOptions =>
                {
                    httpsOptions.ServerCertificate = ServerCertHelper.GetServerCert();
                    httpsOptions.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.DelayCertificate;
                    httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls13;
                    httpsOptions.AllowAnyClientCertificate();
                });
            });

            // !DEMO! Repo / Token manager services
            builder.Services.AddSingleton<ClientRegistrationsService>();
            //builder.Services.AddHostedService<OtpRegistrationService>();


            // Configure JWT authentication
            var authBuilder = builder.Services.AddAuthentication()
                .AddCertificate(AuthenticationSchemes.Mtls, options =>
                {
                    options.AllowedCertificateTypes = CertificateTypes.All;
                    options.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.Offline;
                    options.RevocationFlag = System.Security.Cryptography.X509Certificates.X509RevocationFlag.EndCertificateOnly;

                    options.ChainTrustValidationMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
                    options.CustomTrustStore = new X509Certificate2Collection(ServerCertHelper.GetServerCert());

                    options.ValidateCertificateUse = true;
                    options.ValidateValidityPeriod = true;

                    options.Events = new CertificateAuthenticationEvents()
                    {
                        OnChallenge = async (context) =>
                        {
                            var cert = context.HttpContext.Connection.ClientCertificate;
                            
                            Console.WriteLine("MTLS CHALLENGE");
                        },
                        OnAuthenticationFailed = async (context) =>
                        {
                            

                            var isSelfSigned = context.HttpContext.Connection.ClientCertificate.IsSelfSigned();

                            //var test2 = context.HttpContext.Connection.ClientCertificate.

                            Console.WriteLine("MTLS AUTHENTICATION FAILURE");
                        },
                        OnCertificateValidated = async (context) =>
                        {
                            var cert = context.ClientCertificate;

                            // try extract client Id from the DN
                            var sid = cert.SubjectName.Name.Replace("CN=", "").Trim();

                            if (!Guid.TryParse(sid, out var clientId))
                            {
                                context.Fail("Unable to parse client Id");
                                return;
                            }

                            var clientService = context.HttpContext.RequestServices.GetRequiredService<ClientRegistrationsService>();
                            var client = clientService.GetClient(clientId);
                            if (client == null)
                            {
                                context.Fail("Client Not Located.");
                            }

                            // check registration status and expiration
                            if (client.RegistrationStatus < ClientRegistrationStatus.Authenticated)
                            {
                                context.Fail("Invalid registration");
                            }

                            // change to BouncyCastle class for simpler PubKey Hash validation
                            var bcCert = new X509CertificateParser().ReadCertificate(cert.RawData);
                            // validate client properties against connection certificate. 
                            if (!client.IsCertValidForRegistration(bcCert))
                            {
                                context.Fail("InvalidCertificateForClient");
                            }

                            // TODO: OTHER CERTIFICATE VALIDATION CHECKS - CDS roles, groups and other specific claims related to client.

                            context.Principal ??= new ClaimsPrincipal();

                            context.Principal.Claims.Prepend(new Claim(ClaimTypes.PrimarySid, sid));

                            
                            

                            //context.HttpContext.User.AddIdentity(new ClaimsPrincipal()
                            //{
                            //    new Claim(ClaimTypes.AuthenticationMethod, AuthenticationSchemes.Mtls),
                                
                            //});

                            
                            context.Success();
                        }
                    };

                    //TODO: Validate thumbprint of certificate against matching client to ensure this is the most recently issued certificate for that client
                })
                //.AddScheme<OtpAuthenticationSchemeOptions, OtpAuthenticationHandler>(AuthenticationSchemes.Otp, options =>
                //{
                //    //todo
                //})
                .AddJwtBearer(AuthenticationSchemes.Oidc, options =>
                {
                //get from config
                    var oidcOptions = builder.Configuration.GetSection("Oidc").Get<OidcOptions>();

                    options.Authority = oidcOptions.Authority;
                    options.Audience = oidcOptions.ClientId;

                    
                    IdentityModelEventSource.ShowPII = true;


                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,

                        ValidateIssuerSigningKey = true,
                        ValidIssuer = oidcOptions.Authority,
                        ValidIssuers = new List<string>() { oidcOptions.Authority, "https://login.microsoftonline.com/d4a22b64-8bb0-467a-b043-f4594957e3b3/v2.0" }
                    };
                        //ClockSkew = TimeSpan.Zero,
                    
                                        // Add a marker for the OIDC authentication scheme in the context's claims identity for use in endpoints
                    options.Events = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents
                    {
                        OnAuthenticationFailed = async (context) =>
                        {
                            IdentityModelEventSource.ShowPII = true;

                            var identity = context.Principal?.Identity;
                        },
                        OnTokenValidated = context =>
                        {
                            IdentityModelEventSource.ShowPII = true;
                            var identity = context.Principal?.Identity as ClaimsIdentity;

                            //if (identity != null)
                            //{
                            //    identity.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, AuthenticationSchemes.Oidc));

                            //    // push token expiration into claims if its only locatable under "exp" so we don't have to look for different types of expiration when generating the CSR
                            //    if (identity.HasClaim(x => x.Type == ClaimTypes.Expiration && !String.IsNullOrEmpty(x.Value)))
                            //    {
                            //        // Get the JWT exp claim
                            //        var expirationTimeStamp = identity.FindFirst("exp")?.Value;
                            //        // set default for 24 hours from now if no expiration found
                            //        expirationTimeStamp ??= new DateTimeOffset(DateTime.UtcNow.AddDays(1), TimeSpan.Zero).ToUnixTimeSeconds().ToString();

                            //        identity.AddClaim(new Claim(ClaimTypes.Expiration, expirationTimeStamp));
                            //    }
                            //}

                            return Task.CompletedTask;
                        },
                        OnChallenge = context =>
                        {
                            Console.WriteLine("JwtChallenge Event");
                            context.Response.Headers.Append(OidcAuthenticationHeaders.Authority, oidcOptions.Authority);
                            context.Response.Headers.Append(OidcAuthenticationHeaders.Audience, oidcOptions.ClientId);
                            context.Response.Headers.Append(OidcAuthenticationHeaders.ClientId, oidcOptions.ClientId);

                            return Task.CompletedTask;
                        }
                    };
            });



            builder.Services.AddAuthorization(options =>
            {
                // interactive an non-interactive both hit the same register endpoint.
                //options.AddPolicy(AuthorizationPolicies.Otp, policy =>
                //    policy.RequireAuthenticatedUser()
                //          .AddAuthenticationSchemes(AuthenticationSchemes.Otp));

                // non-interactive agents don't get auto renew
                options.AddPolicy(AuthorizationPolicies.Oidc, policy =>
                    policy.RequireAuthenticatedUser()
                          .AddAuthenticationSchemes(AuthenticationSchemes.Oidc));

                options.AddPolicy(AuthorizationPolicies.Mtls, policy =>
                    policy.RequireAuthenticatedUser()
                          .AddAuthenticationSchemes(AuthenticationSchemes.Mtls));
            });

        }


        public static void ConfigureDemoApp(this WebApplication app)
        {
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseCors("AllowLocalhost");

            var mtlsGroup = app.MapGroup("/api").RequireAuthorization(AuthorizationPolicies.Mtls);
            // Test method - retrieve clientId from Mtls Certificate
            mtlsGroup.MapGet("/whoami", (HttpContext context, ClientRegistrationsService clientService) =>
            {
                var clientId = context.User.Identity.Name;
                if (string.IsNullOrEmpty(clientId))
                {
                    throw new Exception("Unable to determine Client Id");
                }

                var parsedClientId = Guid.Parse(clientId);
                var client = clientService.GetClient(parsedClientId);

                return Results.Ok(client);

            });
            //... Map any other endpoints under the mtlsGroup so they are automatically registered with the mtls authorizationPolicy;
            // mtlsGroup.MapGet("/...", () => {})...


            // oidc based endpoints for registration and renewal (with updated access token)
            var interactiveGroup = app.MapGroup("/api/interactive").RequireAuthorization(AuthorizationPolicies.Oidc);
            interactiveGroup.MapPost("/register", async (ClientRecord newClient, HttpContext context, ClientRegistrationsService clientService) =>
            {
                X509Certificate2? contextClientCert = await context.Connection.GetClientCertificateAsync();
                if (contextClientCert == null)
                {
                    // client cert required to validate 
                    return Results.Unauthorized();
                }
                var bcClientCert = new X509CertificateParser().ReadCertificate(contextClientCert.RawData);
                if (bcClientCert == null)
                {
                    return Results.Unauthorized();
                }

                if (!newClient.IsCertValidForRegistration(bcClientCert))
                {
                    return Results.Unauthorized();
                }

                // Check if client already registered
                if (clientService.Clients.Any(client => client.Id == newClient.Id))
                {
                    return Results.BadRequest();
                }

                var Email = context.User.FindFirst(ClaimTypes.Email)?.Value;
                var userId = context.User.FindFirst(ClaimTypes.Sid)?.Value;

                newClient.Email = Email;
                newClient.UserId = userId;
                newClient.RegistrationStatus = ClientRegistrationStatus.Authenticated;


                // try create the record in an unregistered state
                clientService.TryAddOrUpdateClient(newClient);

                var expirationTimestamp = context.User.FindFirst("exp")?.Value;
                var expiration = String.IsNullOrEmpty(expirationTimestamp)
                                    ? DateTime.UtcNow.AddHours(1)
                                    : DateTimeOffset.FromUnixTimeSeconds(long.Parse(expirationTimestamp)).Date;


                var signedCert = ServerCertHelper.GenerateCertificate(bcClientCert.GetPublicKey(), newClient.Id, expiration);
                var base64Signed = Convert.ToBase64String(signedCert.GetEncoded());

                context.Response.Headers.Add(ClientAuthenticationHeaders.SignedCertificate, base64Signed);

                return Results.Ok(base64Signed);

            });
            interactiveGroup.MapPost("/Renew", async (Guid clientId, HttpContext context, ClientRegistrationsService clientService) =>
            {
                var contextClientCert = await context.Connection.GetClientCertificateAsync();
                if (contextClientCert == null)
                {
                    return Results.Unauthorized();
                }
                var bcClientCert = new X509CertificateParser().ReadCertificate(contextClientCert.RawData);
                if (bcClientCert == null)
                {
                    return Results.Unauthorized();
                }

                //Check user Email/external sid info against client to ensure this is the same user it was originally registered to
                var client = clientService.GetClient(clientId);
                if (client == null) return Results.BadRequest("invalid clientId");

                // validate 
                if (!client.IsCertValidForRegistration(bcClientCert))
                {
                    return Results.Unauthorized();
                }

                // use oid claim instead of "sub" as "sub" relies on a users registration to the idp app which could be removed and recreated which would then cause
                // this to never validate. oid is the idp's globally unique identifier for the user, not the users registration to the app so it won't change.
                var externalUserId = context.User.FindFirst("sub")?.Value;
                if (externalUserId == null)
                {
                    //No oid (userId) presented in token
                    return Results.Unauthorized();
                }

                // only the user that initially registered the client is allowed to receive the certificate
                if (client.UserId != externalUserId)
                {
                    return Results.Unauthorized();
                }

                
                // TODO: REVOKE OLD CERT

                // get expiration from attached access token;

                var expirationTimestamp = context.User.FindFirst("exp")?.Value;
                var expiration = String.IsNullOrEmpty(expirationTimestamp)
                                    ? DateTime.UtcNow.AddHours(1)
                                    : DateTimeOffset.FromUnixTimeSeconds(long.Parse(expirationTimestamp)).Date;

                
                var signed = ServerCertHelper.GenerateCertificate(bcClientCert.GetPublicKey(), clientId, expiration);

                var base64Signed = Convert.ToBase64String(signed.GetEncoded());

                return Results.Ok(base64Signed);
            });


            // Otp based registration end point
            // 2 endpoints, one for creating the initial registration and then one for verifying it with a one time code
            var nonInteractiveGroup = app.MapGroup("/api/non-interactive"); //.RequireAuthorization(AuthorizationPolicies.Otp);
            nonInteractiveGroup.MapPost("/register", async (ClientRecord newClient, HttpContext context, ClientRegistrationsService clientService) =>
            {
                X509Certificate2? contextClientCert = await context.Connection.GetClientCertificateAsync();
                if (contextClientCert == null)
                {
                    // client cert required to validate 
                    return Results.Unauthorized();
                }
                var bcClientCert = new X509CertificateParser().ReadCertificate(contextClientCert.RawData);
                if (bcClientCert == null)
                {
                    return Results.Unauthorized();
                }

                if (!newClient.IsCertValidForRegistration(bcClientCert))
                {
                    return Results.Unauthorized();
                }

                // Check if client already registered
                if (clientService.Clients.Any(client => client.Id == newClient.Id))
                {
                    return Results.BadRequest();
                }

                newClient.RegistrationStatus = ClientRegistrationStatus.Provisional;

                // try create the record in an unregistered state
                clientService.TryAddOrUpdateClient(newClient);
                //TODO ALERT ADMINISTRATORS
                return Results.Ok();

            });
            nonInteractiveGroup.MapPost("/authenticate", async (HttpContext context, ClientRegistrationsService clientService) => {
                try
                {
                    X509Certificate2? contextClientCert = await context.Connection.GetClientCertificateAsync();
                    if (contextClientCert == null)
                    {
                        // client cert required to validate 
                        return Results.Unauthorized();
                    }
                    var bcClientCert = new X509CertificateParser().ReadCertificate(contextClientCert.RawData);
                    if (bcClientCert == null)
                    {
                        return Results.Unauthorized();
                    }

                    var clientIdString = context.Request.Headers.FirstOrDefault(kvp => kvp.Key == ClientAuthenticationHeaders.ClientId).Value.FirstOrDefault();
                    if (!Guid.TryParse(clientIdString, out var clientId))
                    {
                        Console.WriteLine($"Failed to authenticate non-interactive client -  no client Id header provided");
                        return Results.BadRequest();
                    }
                    var otp = context.Request.Headers.FirstOrDefault(kvp => kvp.Key == ClientAuthenticationHeaders.OtpCode).Value.FirstOrDefault();
                    if (String.IsNullOrWhiteSpace(otp)) {
                        Console.WriteLine($"Failed to authenticate non-interactive client(id:{clientId.ToString()}), no otp header");
                    }

                    var client = clientService.GetClient(clientId);
                    if (client == null) {
                        // client doesn't exist
                        return Results.BadRequest();
                    }

                    // validate client against context certificate
                    if (!client.IsCertValidForRegistration(bcClientCert))
                    {
                        return Results.Unauthorized();
                    }

                    //try validate the OTP
                    if (!clientService.TryVerifyOTP(clientId, otp))
                    {
                        return Results.Unauthorized();
                    }

                    client.RegistrationStatus = ClientRegistrationStatus.Authenticated;

                    // success
                    //sign a new cert
                    var signedCert = ServerCertHelper.GenerateCertificate(bcClientCert.GetPublicKey(), client.Id, DateTime.UtcNow.AddDays(14));


                    var encodedBytes = signedCert.GetEncoded();

                    var base64EncodedCert = Convert.ToBase64String(encodedBytes);

                    context.Response.Headers.Append(ClientAuthenticationHeaders.SignedCertificate, base64EncodedCert);

                    return Results.Ok();

                } catch {
                    return Results.BadRequest();
                }
            });


            // this should be configured under a different project in the live system - set like this for demo with swagger
            var adminGroup = app.MapGroup("/api/admin").AllowAnonymous();
            adminGroup.MapGet("/clients", (ClientRegistrationsService clientService) => {
                var clients = clientService.Clients.Select(client => new
                {
                    Client = client
                });
                return Results.Ok(clients);
            });
            adminGroup.MapGet("/generate-client-otp/{clientId}", (Guid clientId, ClientRegistrationsService clientService) =>
            {
                var client = clientService.GetClient(clientId);
                if (client == null) return Results.BadRequest();

                // only non-interactive clients get an otp
                if (client.IsInteractiveClient) return Results.BadRequest();

                // code gets returned to user who generated it and is never able to be viewed again.
                if (!clientService.TryGetClientOTP(clientId, out var otpCode)) {
                    return Results.BadRequest();
                }

                return Results.Ok(otpCode);
            });

        }
    }
}
