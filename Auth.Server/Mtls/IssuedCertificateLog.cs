//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;

//namespace Auth.Server.Mtls
//{
//    public class IssuedCertificateLog
//    {
//        public Guid Id { get; set; } = Guid.NewGuid();

//        /// <summary>
//        /// Id of the client record this is attached to
//        /// </summary>
//        public required Guid ClientId { get; set; }
//        public required string CertificateThumbprint { get; set; }
//        public required DateTime IssuedOn { get; set; }
//        public required DateTime ExpiresOn { get; set; }
//    }
//}
