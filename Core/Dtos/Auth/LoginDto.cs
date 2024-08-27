using System.ComponentModel.DataAnnotations;

namespace AuthRoleBased.Core.Dtos
{
    public class LoginDto
    {
        [Required(ErrorMessage = "Email is required")]
        public required string Email { get; set; } 

        [Required(ErrorMessage = "Password is required")]
        public required string Password { get; set; }
    }
}