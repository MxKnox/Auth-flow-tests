
using Microsoft.Extensions.Hosting;
using Auth.Common;
using Auth.Client.Oidc;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);


var client = new InteractiveClientRegistrationHelper();

const string RedirectUri = "http://localhost:5000/callback";
const string ServerUri = "https://localhost:7264";

Console.WriteLine($"Using server: {ServerUri}");
Console.WriteLine($"Press Enter to connect");
Console.ReadLine();
await client.RegisterClient(ServerUri);

Console.WriteLine("Authenticated, Press enter to try reflecting infomration about the client using mtls");
Console.ReadLine();

await client.ReflectClientInfo();
Console.WriteLine("....done");


