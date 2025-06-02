using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Common
{

    public class ClientRecord
    {
        public required Guid Id { get; set; }
        public required string Host { get;set; }
        
        /// <summary>
        /// User if registered with an oidc based user
        /// </summary>
        public string? UserId { get; set; }
        public string? Name { get; set; }
        public string? Email { get; set; }
        public string? PhoneNumber { get; set; }
        public required bool IsInteractiveClient { get; set; }
        public required string PublicKeyHash { get; set; }
        public ClientRegistrationStatus RegistrationStatus { get; set; } = ClientRegistrationStatus.Provisional;
    }

    
    // temp class for holding the certificate info
    public class ClientCredentials
    {
        /// <summary>
        /// Base 64 encoded x509 certificate signed by the servers CA
        /// </summary>
        public string? SignedCertificate { get; set; }
        /// <summary>
        /// Expiration of current certificate so it can be renewed.
        /// </summary>
        public DateTime? Expires { get; set; }
        public string? PublicKey { get; set; }
        public string? PrivateKey { get; set; }
    }

    
    public enum ClientRegistrationStatus
    {
        Denied = -2,
        Cancelled = -1,
        Provisional = 0,
        Authenticated = 1,
        Authorized = 2,
    }
}
