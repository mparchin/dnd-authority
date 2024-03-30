namespace authority.Schema
{
    public class Profile(User user)
    {
        public Guid Guid { get; set; } = user.Guid;
        public string Name { get; set; } = user.Name;
        public string Email { get; set; } = user.Email;
        public string? Role { get; set; } = user.Role;
        public DateTime? LastLogIn { get; set; } = user.LastLogIn;
        public DateTime UpdatedAt { get; set; } = user.UpdatedAt;
    }

    public class PasswordLogin
    {
        public string Email { get; set; } = "";
        public string Password { get; set; } = "";
    }

    public class RegisterInfo
    {
        public string Name { get; set; } = "";
        public string Email { get; set; } = "";
        public string Password { get; set; } = "";
    }

    public class ResetPassword
    {
        public string Email { get; set; } = "";
        public string? ResetToken { get; set; }
        public string? Password { get; set; }
    }

    public class ChangePassword
    {
        public string Password { get; set; } = "";
        public string NewPassword { get; set; } = "";
    }
}