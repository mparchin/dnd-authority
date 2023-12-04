using Microsoft.EntityFrameworkCore;

namespace authority
{
    public class Db(DbContextOptions<Db> options) : DbContext(options)
    {
        public static string GetProductionDbConnetion(WebApplicationBuilder builder) =>
            $"USER ID={builder.Configuration.GetValue<string>("Postgres_User") ?? "postgres"};" +
            $"Password={builder.Configuration.GetValue<string>("Postgres_Password") ?? "postgres"};" +
            $"Server={builder.Configuration.GetValue<string>("Postgres") ?? "localhost"};" +
            $"Port={builder.Configuration.GetValue<string>("Postgres_Port") ?? "5432"};" +
            $"Database={builder.Configuration.GetValue<string>("Postgres_Db") ?? "authority"};" +
            $"Integrated Security=true;" +
            $"Pooling=true;";

        public DbSet<DbUser> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder) =>
            modelBuilder.UseIdentityAlwaysColumns();
    }
}