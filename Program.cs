using System.Security.Claims;
using System.Security.Cryptography;
using authority;
using authority.Schema;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Extensions.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.OpenApi.Models;

var publicKey = RSA.Create();
publicKey.ImportFromPem(File.ReadAllText(".public.pem").ToCharArray());
var privateKey = RSA.Create();
privateKey.ImportFromPem(File.ReadAllText(".private.pem").ToCharArray());

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

builder.Services.AddSingleton<IAlgorithmFactory>(new RSAlgorithmFactory(publicKey));
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtAuthenticationDefaults.AuthenticationScheme;
}).AddJwt(options =>
{
    options.OnSuccessfulTicket = (logger, ticket) =>
    {
        var user = ticket.Principal.GetUser();
        if (user.Issuer != "dnd-authority")
            return AuthenticateResult.Fail(new Exception("Unknown issuer authority"));
        if (!user.Audience.Contains("dnd-api"))
            return AuthenticateResult.Fail(new Exception("App is not in scope of token"));
        if (user.Expiration <= DateTime.UtcNow)
            return AuthenticateResult.Fail(new Exception("Token is expired"));
        if (user.IssuedAt >= DateTime.UtcNow)
            return AuthenticateResult.Fail(new Exception("Token is tampered with"));
        return AuthenticateResult.Success(ticket);
    };
});

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

app.MapPost("/Login", (PasswordLogin login) =>
    "Bearer " + JwtBuilder.Create()
        .WithAlgorithm(new RS256Algorithm(publicKey, privateKey))
        .AddClaims(new User
        {
            Email = "mmzparchin@gmail.com",
            Password = "test",
            Name = "Mohammad Parchin",
            Role = "Super-Admin",
            LastLogIn = DateTime.UtcNow.AddDays(-1),
        }
        .ToJwtUser("dnd-authority", DateTime.UtcNow.AddDays(1), "dnd-api")
        .GetClaims())
        .Encode())
    .WithTags("Logins")
    .WithDescription("Login using username and password")
    .WithOpenApi();

app.MapGet("/me", (ClaimsPrincipal principal) => new Profile(principal.GetUser()))
    .RequireAuthorization(options => options.RequireClaim("name", "Mohammad Parchin"))
    .WithOpenApi();


app.Run();
