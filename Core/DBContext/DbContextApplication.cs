using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthRoleBased.Core.DBContext
{
    public class DbContextApplication: IdentityDbContext
    {
        public DbContextApplication(DbContextOptions<DbContextApplication> options): base(options)
        {
            
        }
    }
}