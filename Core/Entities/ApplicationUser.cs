using Microsoft.AspNetCore.Identity;

namespace AuthRoleBased.Core.Entities
{
    public class ApplicationUser: IdentityUser
    {
        public required string FirstName { get; set; }
        public required string LastName { get; set; }
        public required string Role { get; set; }
    }
}