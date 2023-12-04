using System.Security.Cryptography;

namespace authority
{
    public interface IPublicRSAProvider
    {
        public RSA PublicKey { get; }
    }
    public interface IPrivateRSAProvider
    {
        public RSA PrivateKey { get; }
    }

    public class PublicRSAProvider : IPublicRSAProvider
    {
        public RSA PublicKey { get; }
        public PublicRSAProvider()
        {
            PublicKey = RSA.Create();
            PublicKey.ImportFromPem(File.ReadAllText(".public.pem").ToCharArray());
        }
    }
    public class PrivateRSAProvider : IPrivateRSAProvider
    {
        public RSA PrivateKey { get; }
        public PrivateRSAProvider() : base()
        {
            PrivateKey = RSA.Create();
            PrivateKey.ImportFromPem(File.ReadAllText(".private.pem").ToCharArray());
        }
    }
}