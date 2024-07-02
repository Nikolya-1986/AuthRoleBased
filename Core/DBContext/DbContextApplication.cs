using AuthRoleBased.Core.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthRoleBased.Core.DBContext
{
    public class DbContextApplication: IdentityDbContext<ApplicationUser>
    {
        public DbContextApplication(DbContextOptions<DbContextApplication> options): base(options)
        {
            
        }
    }
}