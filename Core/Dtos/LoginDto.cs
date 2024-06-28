using System.ComponentModel.DataAnnotations;

namespace AuthRoleBased.Core.Dtos
{
    public class LoginDto
    {
        [Required(ErrorMessage = "UserName is required")]
        public required string UserName { get; set; } 

        [Required(ErrorMessage = "Password is required")]
        public required string Password { get; set; }
    }
}