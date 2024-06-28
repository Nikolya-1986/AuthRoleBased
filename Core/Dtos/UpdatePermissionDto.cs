using System.ComponentModel.DataAnnotations;

namespace AuthRoleBased.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "UserName is required")]
        public required string UserName { get; set; } 
    }
}