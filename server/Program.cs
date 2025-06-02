
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Certificate;
using Auth.Server.Otp;
using Auth.Server;
using System.Security.Cryptography.X509Certificates;
using Microsoft.OpenApi.Models;
using Microsoft.IdentityModel.Logging;

var builder = WebApplication.CreateBuilder(args);

// services and auth handler mappings
builder.ConfigureDemoServices();

// add swagger for demo
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "AuthSchemesPoc", Version = "v1" });
});


// Add CORS for local development
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalhost", policy =>
    {
        policy.WithOrigins("http://localhost:3000", "http://localhost:5000")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();



// route mapping etc.
app.ConfigureDemoApp();

// enable swagger for demo
app.UseSwagger();
app.UseSwaggerUI();


app.Run();

//enable PII logging for dev
IdentityModelEventSource.ShowPII = true;