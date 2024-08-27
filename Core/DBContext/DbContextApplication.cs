using AuthRoleBased.Core.Dtos;
using AuthRoleBased.Core.Dtos.Auth;
using AuthRoleBased.Core.Dtos.User;
using AuthRoleBased.Core.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthRoleBased.Core.DBContext
{
    public class DbContextApplication: IdentityDbContext<ApplicationUser>
    {
        private readonly DbContextOptions _options;
        public DbContextApplication(DbContextOptions<DbContextApplication> options): base(options)
        {
            _options = options;
        }
        public DbSet<BasicUserInformation>? BasicUserInformation { get; set; }
        public DbSet<RefreshToken>? RefreshTokens { get; set; }
    }
}