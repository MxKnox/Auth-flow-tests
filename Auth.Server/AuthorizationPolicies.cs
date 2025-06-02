using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Server
{
    public static class AuthorizationPolicies
    {
        public const string Otp = "OtpPolicy";
        public const string Oidc = "OidcPolicy";
        public const string Mtls = "MtlsPolicy";
    }
}
