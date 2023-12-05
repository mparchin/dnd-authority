using JWT.Algorithms;
using JWT.Builder;
using Newtonsoft.Json;

namespace authority
{
    public class JWTToken
    {
        public string? Token { get; set; } = "";
        public long? Expiration { get; set; }
        public string? RefreshToken { get; set; } = "";
        public long? RefreshExpiration { get; set; }
    }
    public interface IJWTTokenFactoryOptions
    {
        public TimeSpan Expiration { get; set; }
        public TimeSpan RefresExpiration { get; set; }
        public string Authority { get; set; }
        public string[] Audience { get; set; }
    }
    public class JWTTokenFactoryOptions(TimeSpan expiration, TimeSpan refresExpiration, string authority, string[] audiance)
        : IJWTTokenFactoryOptions
    {
        public TimeSpan Expiration { get; set; } = expiration;
        public TimeSpan RefresExpiration { get; set; } = refresExpiration;
        public string Authority { get; set; } = authority;
        public string[] Audience { get; set; } = audiance;
    }
    public interface IJWTTokenFactory
    {
        public JWTToken Sign(User user);
        public JWTToken Refresh(JWTToken token);
    }
    public class JWTTokenFactory(IPrivateRSAProvider @private, IPublicRSAProvider @public,
        IJWTTokenFactoryOptions JWTTokenFactoryOptions) : IJWTTokenFactory
    {
        private readonly IPrivateRSAProvider _private = @private;
        private readonly IPublicRSAProvider _public = @public;
        private readonly IJWTTokenFactoryOptions _options = JWTTokenFactoryOptions;

        public JWTToken Refresh(JWTToken token)
        {
            var user = (JsonConvert.DeserializeObject<Dictionary<string, string>>(JwtBuilder.Create()
                    .WithAlgorithm(new RS256Algorithm(_public.Key, _private.Key))
                    .MustVerifySignature()
                    .Decode(token.RefreshToken))?
                .GetUser()) ?? throw new Exception("Refresh token is tampered with");
            user?.VerifyJWTToken();
            return Sign(user!);
        }

        public JWTToken Sign(User user) =>
            new()
            {
                Token = JwtBuilder.Create()
                    .WithAlgorithm(new RS256Algorithm(_public.Key, _private.Key))
                    .AddClaims(user
                        .ToJwtUser(_options.Authority, DateTime.UtcNow.Add(_options.Expiration), _options.Audience)
                        .GetClaims())
                    .Encode(),
                Expiration = DateTime.UtcNow.Add(_options.Expiration).ToEpoch(),
                RefreshToken = JwtBuilder.Create()
                    .WithAlgorithm(new RS256Algorithm(_public.Key, _private.Key))
                    .AddClaims(user
                        .ToJwtUser(_options.Authority, DateTime.UtcNow.Add(_options.RefresExpiration), _options.Authority)
                        .GetClaims())
                    .Encode(),
                RefreshExpiration = DateTime.UtcNow.Add(_options.RefresExpiration).ToEpoch()
            };

    }
}