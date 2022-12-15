using System;
using Microsoft.EntityFrameworkCore;

namespace auth_service.Entities
{
    public class HyderionDbContext : DbContext
    {


        private ServerVersion mysqlVersion = new MySqlServerVersion(new Version(8, 0, 30));
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseMySql(connectionString: AppConfig.HyderionConnectionString(), mysqlVersion);
        }

        public DbSet<User> Users { get; set; }


    }
}

