using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Common
{
    public static class ClientAuthenticationHeaders
    {
        /// <summary>
        /// All requests should include this
        /// </summary>
        public const string ClientId = "X-Client-Id";

        /// <summary>
        /// Only OTP authenticate calls need to use this header
        /// </summary>
        public const string OtpCode = "OTP-Code";

        /// <summary>
        /// Header used when returning a signed certificate from any of the Auth flows.
        /// </summary>
        public const string SignedCertificate = "X-Signed-Cert";
    }
}
