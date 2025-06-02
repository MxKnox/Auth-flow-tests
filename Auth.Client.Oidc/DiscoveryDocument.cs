using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Common
{
    public class DiscoveryDocument
    {
        public string? AuthorizationEndpoint { get; set; }
        public string? TokenEndpoint { get; set; }
        public string? UserinfoEndpoint { get; set; }
        public string? JwksUri { get; set; }
    }
}
