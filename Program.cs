using System.Security.Claims;
using authority;
using authority.Schema;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
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

if (builder.Environment.IsDevelopment())
    builder.Services.AddDbContext<Db>(options =>
    {
        options.UseNpgsql(Db.GetDbConnetion(builder));
        options.EnableSensitiveDataLogging();
    });
else
    builder.Services.AddDbContext<Db>(options => options.UseNpgsql(Db.GetDbConnetion(builder)));


builder.Services.AddSingleton<IPrivateRSAProvider>(
    new PrivateRSAProvider(builder.Configuration.GetValue<string>("Private_Key") ?? ".private.pem"));

builder.Services.AddSingleton<IJWTTokenFactoryOptions>(new JWTTokenFactoryOptions(
    TimeSpan.FromHours(Convert.ToInt32(builder.Configuration.GetValue<string>("Token_Expiration_Hours") ?? "24")),
    TimeSpan.FromDays(Convert.ToInt32(builder.Configuration.GetValue<string>("Refresh_Expiration_Days") ?? "30")),
    builder.Configuration.GetValue<string>("Authority") ?? "dnd-authority",
    (builder.Configuration.GetValue<string>("Audiance") ?? "dnd-authority,dnd-api").Split(',')
));
builder.Services.AddSingleton<IJWTTokenFactory, JWTTokenFactory>();


builder.AddJWTAuthentication();

builder.Services.AddAuthorization(options =>
{

});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    if (scope.ServiceProvider.GetService<Db>() is { } db)
    {
        await db.Database.MigrateAsync();
        if (builder.Environment.IsDevelopment())
        {
            //seed
        }
    }
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

// app.MapPost("/register",)

app.MapPost("/refresh", Results<UnauthorizedHttpResult, Ok<JWTToken>> (JWTToken token, IJWTTokenFactory tokenFactory, ILogger<Program> logger) =>
{
    try
    {
        return TypedResults.Ok(tokenFactory.Refresh(token));
    }
    catch (Exception ex)
    {
        logger.LogWarning(ex.Message);
    }
    return TypedResults.Unauthorized();
})
.WithTags("authority")
.WithDescription("Refreshing provided token")
.WithOpenApi();

app.MapPost("/login", Results<UnauthorizedHttpResult, Ok<JWTToken>> (PasswordLogin login, IJWTTokenFactory tokenFactory) =>
{
    try
    {
        return TypedResults.Ok(tokenFactory.Sign(new User
        {
            Email = "mmzparchin@gmail.com",
            Password = "test",
            Name = "Mohammad Parchin",
            Role = "Super-Admin",
            LastLogIn = DateTime.UtcNow,
        }));
    }
    catch { }
    return TypedResults.Unauthorized();
})
.WithTags("authority")
.WithDescription("Login using username and password")
.WithOpenApi();

app.MapGet("/me", (ClaimsPrincipal principal) => new Profile(principal.GetUser()))
    .RequireAuthorization(options => options.RequireAuthenticatedUser())
    .WithTags("authority")
    .WithDescription("Getting current user's info")
    .WithOpenApi();


app.Run();
