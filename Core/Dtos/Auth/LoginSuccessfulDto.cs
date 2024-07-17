using AuthRoleBased.Core.Dtos.User;

namespace AuthRoleBased.Core.Dtos.Auth
{
    public class LoginSuccessfulDto<TokenDto> : BasicUserInformation
    {
        public TokenDto Tokens { get; set; }
    }
}