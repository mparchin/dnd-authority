using System.Security.Claims;

namespace authority
{
    public class User
    {
        public Guid Guid { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = "";
        public string Email { get; set; } = "";
        public string Password { get; set; } = "";
        public string? Role { get; set; }
        public DateTime? LastLogIn { get; set; }
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    }

    public class DbUser : User
    {
        public int Id { get; set; }
    }

    public class JWTUser : User
    {
        public string Issuer { get; set; } = "";
        public string[] Audience { get; set; } = [];
        public DateTime Expiration { get; set; }
        public DateTime IssuedAt { get; set; } = DateTime.UtcNow;

        public JWTUser() : base() { }
        public JWTUser(User user) : base()
        {
            Guid = user.Guid;
            Name = user.Name;
            Email = user.Email;
            Password = user.Password;
            Role = user.Role;
            LastLogIn = user.LastLogIn;
            UpdatedAt = user.UpdatedAt;
        }
    }

    public static class JWTUserExtension
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
    }
}