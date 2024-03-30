using MailKit.Net.Smtp;
using MimeKit;

namespace authority
{
    public interface IMail
    {
        public Task SendResetAsync(DbUser user);
    }


    public class Mail(string host, int port, bool ssl, string user, string password,
        string fromEmail, string fromName, string textFileAddress, string htmlFileAddress,
        string resetLink, ILogger logger) : IMail
    {
        private readonly string _host = host;
        private readonly int _port = port;
        private readonly bool _ssl = ssl;
        private readonly string _user = user;
        private readonly string _password = password;
        private readonly string _fromEmail = fromEmail;
        private readonly string _fromName = fromName;
        private readonly string _textFileAddress = textFileAddress;
        private readonly string _htmlFileAddress = htmlFileAddress;
        private readonly string _resetLink = resetLink;
        private readonly ILogger _logger = logger;

        public async Task SendResetAsync(DbUser user)
        {
            if (_host == "")
            {
                _logger.LogWarning("Email client is disabled");
                return;
            }

            var message = new MimeMessage();
            var link = _resetLink.Replace("{EMAIL}", user.Email).Replace("{TOKEN}", user.ResetToken);

            message.From.Add(new MailboxAddress(_fromName, _fromEmail));
            message.To.Add(new MailboxAddress($"Dear {user.Name}", user.Email));
            message.Subject = "Reset Eldoria Password";
            message.Body = new BodyBuilder
            {
                TextBody = (await File.ReadAllTextAsync(_textFileAddress)).Replace("{{LINK}}", link).Replace("{{NAME}}", user.Name),
                HtmlBody = (await File.ReadAllTextAsync(_htmlFileAddress)).Replace("{{LINK}}", link).Replace("{{NAME}}", user.Name)
            }.ToMessageBody();

            try
            {
                using var smtp = new SmtpClient();
                await smtp.ConnectAsync(_host, _port, _ssl);
                await smtp.AuthenticateAsync(_user, _password);
                await smtp.SendAsync(message);
                await smtp.DisconnectAsync(true);

            }
            catch (Exception e)
            {
                _logger.LogError("Failed to send Mail: {exception}", e);
            }

        }
    }
}
