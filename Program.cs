using System.Security.Claims;
using authority;
using authority.Schema;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;


var builder = WebApplication.CreateBuilder(args);

Console.WriteLine($"Running app in {builder.Environment.EnvironmentName} mode");

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
builder.Services.AddScoped<IPasswordHasher, PasswordHasher>();
builder.Services.AddScoped<IUserService, UserService>();

builder.AddJWTAuthentication();
builder.Services.AddAuthorization();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    if (scope.ServiceProvider.GetService<Db>() is { } db &&
        scope.ServiceProvider.GetService<IUserService>() is { } userService)
    {
        await db.Database.MigrateAsync();
        await userService.SeedAdminsAsync(
            [.. (builder.Configuration.GetValue<string>("Admin_User_Emails") ?? "a@a.a,b@b.b").Split(',')],
            [.. (builder.Configuration.GetValue<string>("Admin_User_Names") ?? "aaa,bbb").Split(',')],
            [.. (builder.Configuration.GetValue<string>("Admin_User_Password") ?? "ab123,ab123").Split(',')]);
    }
}

app.UseCors(builder =>
{
    builder.AllowAnyHeader();
    builder.AllowAnyMethod();
    builder.AllowAnyOrigin();
});

app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapPost("/register", async Task<Results<BadRequest<string>, Ok<JWTToken>>> (RegisterInfo registerInfo,
    IJWTTokenFactory tokenFactory, Db db, IUserService userService) =>
{
    try
    {
        var user = await userService.SignUpAsync(new User
        {
            Email = registerInfo.Email,
            Name = registerInfo.Name
        }, registerInfo.Password);

        user.LastLogIn = DateTime.UtcNow;
        await db.SaveChangesAsync();

        return TypedResults.Ok(tokenFactory.Sign(user));
    }
    catch { }
    return TypedResults.BadRequest(registerInfo.Email);
})
.AllowAnonymous()
.WithTags("authority")
.WithDescription("Create new user for application")
.WithOpenApi();

app.MapPost("/refresh", Results<UnauthorizedHttpResult, Ok<JWTToken>>
    (JWTToken token, IJWTTokenFactory tokenFactory, ILogger<Program> logger) =>
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
.AllowAnonymous()
.WithTags("authority")
.WithDescription("Refreshing provided token")
.WithOpenApi();

app.MapPost("/login", async Task<Results<UnauthorizedHttpResult, Ok<JWTToken>>> (PasswordLogin login,
    IJWTTokenFactory tokenFactory, IUserService userService) =>
{
    try
    {
        return TypedResults.Ok(tokenFactory.Sign(await userService
            .SignInAsync(login.Email, login.Password)));
    }
    catch { }
    return TypedResults.Unauthorized();
})
.AllowAnonymous()
.WithTags("authority")
.WithDescription("Login using email and password")
.WithOpenApi();

app.MapGet("/me", (ClaimsPrincipal principal) => new Profile(principal.GetUser()))
.RequireAuthorization(Authorization.User)
.WithTags("authority")
.WithDescription("Getting current user's info")
.WithOpenApi();


app.Run();
