using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Common.Oidc
{
    /// <summary>
    /// Used for sending information about the OIDC Authority out to agents as they register.
    /// </summary>
    public static class OidcAuthenticationHeaders
    {
        public const string Authority = "Oidc-Authority";
        public const string Audience = "Oidc-Audience";
        public const string ClientId = "Oidc-ClientId";
    }

}
