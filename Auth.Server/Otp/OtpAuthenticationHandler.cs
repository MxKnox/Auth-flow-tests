//using Auth.Common.Otp;
//using Microsoft.AspNetCore.Authentication;
//using Microsoft.AspNetCore.Mvc.Routing;
//using Microsoft.Extensions.Logging;
//using Microsoft.Extensions.Options;
//using System.Security.Claims;
//using System.Text.Encodings.Web;

//namespace Auth.Server.Otp
//{
//    public class OtpAuthenticationHandler : AuthenticationHandler<OtpAuthenticationSchemeOptions>
//    {
//        private readonly OtpRegistrationService _otpService;
//        public OtpAuthenticationHandler(
//            IOptionsMonitor<OtpAuthenticationSchemeOptions> options,
//            ILoggerFactory logger, 
//            UrlEncoder encoder,
//            OtpRegistrationService otpService
//            )
//            : base(options, logger, encoder)
//        {
//            _otpService = otpService;
//        }

//        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
//        {
//            if (!Request.Headers.TryGetValue(OtpAuthenticationHeaders.ClientId, out var clientIdString))
//            {
//                // no id provided to register OTP against.
//                return AuthenticateResult.Fail(new Exception($"missing required header: {OtpAuthenticationHeaders.ClientId}"));
//            }

//            if (String.IsNullOrEmpty(clientIdString) || !Guid.TryParse( clientIdString, out var clientId))
//            {
//                // clent Id failed to parse.
//                return AuthenticateResult.Fail(new Exception("Invalid Client Id"));
//            }

//            if (!Request.Headers.TryGetValue(OtpAuthenticationHeaders.Otp, out var otpToken) || String.IsNullOrEmpty(otpToken))
//            {
//                return AuthenticateResult.Fail(new Exception($"missing required header: {OtpAuthenticationHeaders.Otp}"));
//            }
//            // Validate OTP token
//            if (!_otpService.TryValidateOtp(otpToken, clientId, out var otpRecord)) {
//                return AuthenticateResult.Fail("Invalid OTP token");
//            }

//            // Calc max Expiration date from token.
//            var claims = new[]
//            {
//                new Claim(ClaimTypes.AuthenticationMethod, AuthenticationSchemes.Otp),
//                new Claim("sub", clientIdString),
//                new Claim("exp", otpRecord.RegistrationExpirationTimeStamp.ToString())
//            };

//            var identity = new ClaimsIdentity(claims, Scheme.Name);
//            var principal = new ClaimsPrincipal(identity);
//            var ticket = new AuthenticationTicket(principal, Scheme.Name);

//            return AuthenticateResult.Success(ticket);
//        }

//    }
//}
