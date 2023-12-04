using System.Security.Claims;
using JWT.Algorithms;
using JWT.Extensions.AspNetCore;
using Microsoft.AspNetCore.Authentication;

namespace authority
{
    public static class JWTExtension
    {
        private static readonly List<(string key, Func<JWTUser, string> get, Action<JWTUser, string> set)> _keys =
        [
            ("iss", (user) => user.Issuer, (user, value) => user.Issuer = value),
            ("sub", (user) => user.Guid.ToString(), (user, value) => user.Guid = Guid.Parse(value)),
            ("aud", (user) => user.Audience.Aggregate("", (current,next) => current == "" ? next : $"{current},{next}"),
                (user, value) => user.Audience = value.Split(",")),
            ("exp", (user) => user.Expiration.ToEpoch().ToString(),
                (user, value) => user.Expiration = Convert.ToInt64(value).ToDateTime()),
            ("iat", (user) => user.IssuedAt.ToEpoch().ToString(),
                (user, value) => user.IssuedAt = Convert.ToInt64(value).ToDateTime()),
            ("name", (user) => user.Name, (user, value) => user.Name = value),
            ("email", (user) => user.Email, (user, value) => user.Email = value),
            ("role", (user) => user.Role ?? "", (user, value) => user.Role = value),
            ("llat", (user) => user.LastLogIn?.ToEpoch().ToString() ?? "",
                (user, value) => user.LastLogIn = Convert.ToInt64(value).ToDateTime()),
            ("upat", (user) => user.UpdatedAt.ToEpoch().ToString(),
                (user, value) => user.UpdatedAt = Convert.ToInt64(value).ToDateTime()),
        ];
        private static long ToEpoch(this DateTime dateTime) =>
            Convert.ToInt64((dateTime.ToUniversalTime() - new DateTime(1970, 1, 1)).TotalMilliseconds);

        public static DateTime ToDateTime(this long epoch) =>
            DateTimeOffset.FromUnixTimeMilliseconds(epoch).DateTime.ToUniversalTime();

        public static JWTUser ToJwtUser(this User user, string issuer, DateTime expiration, params string[] audiance) =>
            new(user)
            {
                Issuer = issuer,
                Expiration = expiration,
                Audience = audiance
            };

        public static IEnumerable<KeyValuePair<string, object>> GetClaims(this JWTUser user) =>
            _keys.Select(key => KeyValuePair.Create<string, object>(key.key, key.get(user)))
                .Where((pair) => pair.Value.ToString() != "");

        public static JWTUser GetUser(this ClaimsPrincipal principal)
        {
            var user = new JWTUser();
            principal.Claims.ToList().ForEach(claim =>
            {
                if (_keys.FirstOrDefault(key => key.key == claim.Type) is { } found)
                    found.set(user, claim.Value);
            });
            return user;
        }

        public static void AddJWTAuthentication(this IServiceCollection services)
        {
            services.AddSingleton<IPublicRSAProvider>(new PublicRSAProvider());
            services.AddSingleton<IPrivateRSAProvider>(new PrivateRSAProvider());

            services.AddSingleton<IAlgorithmFactory>(sp =>
                new RSAlgorithmFactory(sp.GetRequiredService<IPublicRSAProvider>().PublicKey));

            services.AddAuthentication(options =>
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
        }
    }
}