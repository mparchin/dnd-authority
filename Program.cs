using System.Security.Claims;
using System.Security.Cryptography;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Extensions.AspNetCore;
using Microsoft.OpenApi.Models;

var publicKey = RSA.Create();
publicKey.ImportFromPem(File.ReadAllText(".public.pem").ToCharArray());

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JSON Web Token based security"
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement{
        {
        new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
            }
        },
        Array.Empty<string>()
    }
    });
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtAuthenticationDefaults.AuthenticationScheme;
}).AddJwt(options =>
{
    // secrets, required only for symmetric algorithms, such as HMACSHA256Algorithm
    // options.Keys = new[] { "mySecret" };
    options.PayloadType = typeof(Dictionary<string, object>);

    // optionally; disable throwing an exception if JWT signature is invalid
    // options.VerifySignature = false;
});
builder.Services.AddSingleton<IAlgorithmFactory>(new RSAlgorithmFactory(publicKey));
builder.Services.AddAuthorization(options =>
{

});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello World!")
   .WithTags("Main")
   .WithDescription("Main function")
   .WithOpenApi();

app.MapPost("/Login", (string username, string pass) =>
{
    var @private = RSA.Create();
    @private.ImportFromPem(File.ReadAllText(".private.pem").ToCharArray());

    return JwtBuilder.Create()
                .WithAlgorithm(new RS256Algorithm(publicKey, @private))
                .AddClaim("iss", "dnd-authority")
                .AddClaim("sub", "mmzparchin@gmail.com")
                .AddClaim("aud", new List<string> { "dnd-api" }.Aggregate("", (current, next) => current == "" ? next : $"{current},{next}"))
                .AddClaim("exp", DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeMilliseconds())
                .AddClaim("iat", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                .AddClaim("name", "Mohammad Parchin")
                .AddClaim("email", "mmzparchin@gmail.com")
                .Encode();

})
.WithTags("Logins")
.WithDescription("Login using username and password")
.WithOpenApi();

app.MapGet("/me", (ClaimsPrincipal user) =>
{
    return user.Claims.Select(c => new { c.Type, c.Value, c.ValueType });
}).RequireAuthorization(options => options.RequireClaim("name", "Mohammad Parchin"))
.WithOpenApi();


app.Run();
