using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Server.Otp
{
    public class OtpRecord
    {
        public Guid Id { get; set; } = Guid.NewGuid();

        public required Guid ClientId {get;set;}

        public DateTime CreatedDateTime { get; set; } = DateTime.UtcNow;
        public DateTime CodeExpirationDate { get; set; }

        // Hashed OTP with provided Salt;
        public required string VerificationCode { get; set; }


        // to track when an OTP was used
        public bool Consumed { get; set; }

    }
}
