using System.ComponentModel.DataAnnotations;

namespace AuthRoleBased.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "UserName is required")]
        public string UserName { get; set; } 
    }
}