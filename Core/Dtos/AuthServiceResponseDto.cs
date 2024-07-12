using AuthRoleBased.Core.Dtos.OtherObjects;

namespace AuthRoleBased.Core.Dtos
{
    public class AuthServiceResponseDto: TokenDto
    {
        public bool IsSucceed { get; set; }
        public required string Message { get; set; }
        public string? Role { get; set;}
    }
}