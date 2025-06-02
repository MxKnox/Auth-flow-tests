using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Common.Oidc
{
    public class OidcOptions
    {
        /// <summary>
        /// This will be a fixed URL for the auralis app when one is defined.
        /// </summary>
        public string RedirectUri => "http://localhost:5000/callback"; 

        /// <summary>
        /// OIDC 2.0 base path of Idp
        /// </summary>
        public string Authority = "https://login.microsoftonline.com/common/v2.0";

        /// <summary>
        /// Public Client Id (appId) to use when authenticating with idp
        /// </summary>
        public string ClientId = "7467e935-ebc1-4d31-a652-709d7518195e";

    }
}
