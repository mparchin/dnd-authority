using System.Security.Claims;
using authority;
using authority.Schema;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.OpenApi.Models;


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

builder.Services.AddJWTAuthentication();

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

app.MapPost("/Login", (PasswordLogin login, IPrivateRSAProvider privateProvider, IPublicRSAProvider publicProvider) =>
    "Bearer " + JwtBuilder.Create()
        .WithAlgorithm(new RS256Algorithm(publicProvider.PublicKey, privateProvider.PrivateKey))
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
