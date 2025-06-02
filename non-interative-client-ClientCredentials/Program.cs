// See https://aka.ms/new-console-template for more information
using Auth.Client.Otp;

Console.WriteLine($"Press Enter to attempt to connect to server");
Console.ReadLine();

var otpClient = new OtpClientHelper();

await otpClient.Register();

var Authenticated = false;

Console.WriteLine("Please Enter OTP provided by administrator:");
while (!Authenticated)
{
    var otpInput = Console.ReadLine();
    if(await otpClient.TryAuthenticate(otpInput))
    {
        Console.WriteLine("Authentication Successful");
        Authenticated = true;
        break;
    }
    Console.WriteLine("Authentication unsuccessful, try again.");
}

Console.WriteLine("Attempting to cotact reflection endpoint...");
await otpClient.ReflectClientInfo();

Console.ReadLine();