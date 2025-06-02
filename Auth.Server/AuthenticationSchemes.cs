using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Server
{
    public static class AuthenticationSchemes
    {
        public const string Oidc = "OIDC";
        public const string Otp = "OTP";
        public const string Mtls = "MTLS";
    }
}
