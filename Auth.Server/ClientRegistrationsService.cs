using Auth.Common;
using Auth.Server.Otp;
using Microsoft.AspNetCore.Http.HttpResults;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Server
{
    public class ClientRegistrationsService
    {
        private ConcurrentDictionary<Guid, ClientRecord> registeredClients = new ConcurrentDictionary<Guid, ClientRecord>();
        private ConcurrentDictionary<Guid, OtpRecord> clientOTPs = new ConcurrentDictionary<Guid, OtpRecord>();

        public IQueryable<ClientRecord> Clients => registeredClients.Select(kvp => kvp.Value).AsQueryable();

        public ClientRecord? GetClient(Guid clientId)
        {
            if (!registeredClients.TryGetValue(clientId, out var client))
            {
                return null;
            }

            return client;
        }

        public bool TryAddOrUpdateClient(ClientRecord client)
        {
            if (registeredClients.TryGetValue(client.Id, out var currentValue))
            {
                // client exists
                var result = registeredClients.TryUpdate(client.Id, client, currentValue);
            }

            // client doesn't exist yet, add it
            return registeredClients.TryAdd(client.Id, client);
        }


        public bool TryGetClientOTP(Guid clientId, out string? otpString, DateTime? tokenExpiration = null)
        {
            otpString = null;
            var client = GetClient(clientId);
            if (client == null) return false;


            tokenExpiration ??= DateTime.UtcNow.AddHours(1);

            otpString = GenerateOTP();
            string verifier = string.Empty;

            // Hash the code to securely store it
            Span<byte> hashBytes = SHA256.HashData(Convert.FromHexString(otpString));
            verifier = Convert.ToBase64String(hashBytes);

            var otpOptions = new OtpRecord()
            {
                ClientId = clientId,
                VerificationCode = verifier,
                CodeExpirationDate = tokenExpiration.Value
            };

            // replace existing OTP when new one generated
            if (clientOTPs.TryGetValue(clientId, out var currentOtp))
            {
                clientOTPs.TryUpdate(clientId, otpOptions, currentOtp);
            }else
            {
                clientOTPs.TryAdd(clientId, otpOptions);
            }


            Console.WriteLine($"Admin generated OTP for client:{clientId.ToString()}; OtpHash:{verifier}");
            return true;
        }

        // generate a human readable code as the OTP using HEX Values and cryptographically secure random byte generation
        private string GenerateOTP()
        {
            // Generate 4 random bytes (32 bits)
            byte[] randomBytes = new byte[4];
            var secureRandom = new SecureRandom();

            secureRandom.NextBytes(randomBytes);

            var hexString = Convert.ToHexString(randomBytes);

            return hexString;
        }


        public bool TryVerifyOTP(Guid clientId, string plainOtp)
        {
            try
            {
                if (!clientOTPs.TryGetValue(clientId, out var otpRecord))
                {
                    // no matching otp for client.
                    return false;
                }
                // ignore expired and used codes.
                if (otpRecord.CodeExpirationDate < DateTime.UtcNow )
                {
                    Console.WriteLine($"ClientId:{clientId.ToString()} attempted to use an expired OTP (id: {otpRecord.Id})");
                    return false;
                }
                if (otpRecord.Consumed)
                {
                    Console.WriteLine($"ClientId:{clientId.ToString()} attempted to use a consumed OTP (id:{otpRecord.Id})");
                    return false;
                }

                var codeBytes = Convert.FromHexString(plainOtp);
                var hashedBytes = SHA256.HashData(codeBytes);
                var base64hash = Convert.ToBase64String(hashedBytes);

                if (otpRecord.VerificationCode != base64hash)
                {
                    Console.WriteLine($"ClientId:{clientId.ToString()} Failed OTP verification - Hash didn't match (id:{otpRecord.Id})");
                    return false;
                }

                // hash matched, remove the otp so it can't be used again.
                clientOTPs.TryRemove(clientId, out otpRecord);
                return true;
            }
            catch
            {
                return false;
            }
        }

    }
}
