using System.ComponentModel.DataAnnotations;

namespace AuthRoleBased.Core.Dtos
{
    public class RegisterDto
    {
        [Required(ErrorMessage = "FirstName is required")]
        public required string FirstName { get; set; }

        [Required(ErrorMessage = "LastName is required")]
        public required string LastName { get; set; }

        [Required(ErrorMessage = "UserName is required")]
        public required string UserName { get; set; }

        [Required(ErrorMessage = "Email is required")]
        public required string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public required string Password { get; set; }


    }
}