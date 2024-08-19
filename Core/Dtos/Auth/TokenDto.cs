using AuthRoleBased.Core.Dtos.Auth;

namespace AuthRoleBased.Core.Dtos
{
    public class TokenDto
    {
        public string? AccessToken { get; set;}
        public string? RefreshToken { get; set;}

        public static implicit operator TokenDto(AuthSuccessfulDto<TokenDto> v)
        {
            throw new NotImplementedException();
        }
    }
}