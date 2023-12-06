namespace authority
{
    public static class SeedExtension
    {
        public async static Task SeedAdminsAsync(this IUserService userService, List<string> emails,
            List<string> names, List<string> passwords)
        {
            var admins = emails.Select(email => (email,
                name: names[emails.IndexOf(email)],
                pass: passwords[emails.IndexOf(email)]));

            foreach (var (email, name, pass) in admins)
            {
                if (await userService.ExistsAsync(email))
                {
                    try
                    {
                        await userService.SignInAsync(email, pass);
                    }
                    catch
                    {
                        await userService.ChangePasswordAsync(await userService.GetAsync(email), pass);
                    }
                    return;
                }
                await userService.SignUpAsync(new User
                {
                    Email = email,
                    Name = name,
                    Role = "admin"
                }, pass);
            }

        }
    }
}