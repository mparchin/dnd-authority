using System.Security.Cryptography;

namespace authority
{
    public interface IPasswordHasher
    {
        public void SetPassword(DbUser user, string password);
        public bool VerifyPassword(DbUser user, string password);
        public void GeneratePasswordResetToken(DbUser user);
    }

    public class PasswordHasher(int resetTokenLifeHours = 24) : IPasswordHasher
    {
        private readonly int _resetTokenLifeHours = resetTokenLifeHours;
        private const int KeySize = 128;
        private const int Iterations = 400000;
        private HashAlgorithmName HashAlgorithmName { get; } = HashAlgorithmName.SHA512;

        public void GeneratePasswordResetToken(DbUser user)
        {
            user.ResetToken = Convert.ToHexString(
                Rfc2898DeriveBytes.Pbkdf2(
                    DateTime.UtcNow.ToString("U"),
                    Convert.FromHexString(user.Salt),
                    Iterations,
                    HashAlgorithmName,
                    KeySize));
            user.ResetExpirationTime = DateTime.UtcNow.AddHours(_resetTokenLifeHours);
        }

        public void SetPassword(DbUser user, string password)
        {
            user.Salt = Convert.ToHexString(RandomNumberGenerator.GetBytes(KeySize));
            user.Password = Convert.ToHexString(
                Rfc2898DeriveBytes.Pbkdf2(
                    password,
                    Convert.FromHexString(user.Salt),
                    Iterations,
                    HashAlgorithmName,
                    KeySize));
        }

        public bool VerifyPassword(DbUser user, string password) =>
            CryptographicOperations.FixedTimeEquals(
                Rfc2898DeriveBytes.Pbkdf2(
                    password,
                    Convert.FromHexString(user.Salt),
                    Iterations,
                    HashAlgorithmName,
                    KeySize), Convert.FromHexString(user.Password));
    }
}