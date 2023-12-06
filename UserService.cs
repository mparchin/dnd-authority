using Microsoft.EntityFrameworkCore;

namespace authority
{
    public interface IUserService
    {
        public Task<DbUser> SignUpAsync(User user, string password);
        public Task<DbUser> SignInAsync(string email, string password);
        public Task<DbUser> ChangePasswordAsync(DbUser user, string newPassword);
        public Task<DbUser> ChangePasswordAsync(string email, string currentPassword, string newPassword);
        public Task<bool> ExistsAsync(string email);
        public Task<DbUser> GetAsync(string email);
    }

    public class UserService(Db db, IPasswordHasher passwordHasher) : IUserService
    {
        private readonly IPasswordHasher _passwordHasher = passwordHasher;
        private readonly Db _db = db;

        public async Task<DbUser> ChangePasswordAsync(string email, string currentPassword, string newPassword) =>
            await ChangePasswordAsync(await SignInAsync(email, currentPassword), newPassword);

        public async Task<DbUser> ChangePasswordAsync(DbUser user, string newPassword)
        {
            _passwordHasher.SetPassword(user, newPassword);
            user.UpdatedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync();
            return user;
        }

        public async Task<bool> ExistsAsync(string email) =>
            await _db.Users.AnyAsync(user => user.Email == email);

        public async Task<DbUser> GetAsync(string email) =>
            await _db.Users.FirstAsync(user => user.Email == email);

        public async Task<DbUser> SignInAsync(string email, string password)
        {
            if ((await _db.Users.FirstOrDefaultAsync(user => user.Email == email)) is { } dbUser)
            {
                if (_passwordHasher.VerifyPassword(dbUser, password))
                {
                    dbUser.LastLogIn = DateTime.UtcNow;
                    await _db.SaveChangesAsync();
                    return dbUser;
                }
            }
            throw new Exception("Email or password is incorrect");
        }

        public async Task<DbUser> SignUpAsync(User user, string password)
        {
            if (_db.Users.Any(dbUser => dbUser.Email == user.Email))
                throw new Exception("User exists");

            var dbUser = new DbUser
            {
                Email = user.Email,
                Name = user.Name,
                Role = user.Role
            };

            _passwordHasher.SetPassword(dbUser, password);

            await _db.Users.AddAsync(dbUser);
            await _db.SaveChangesAsync();

            return dbUser;
        }
    }
}