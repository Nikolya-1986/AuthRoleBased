using System.Security.Claims;
using AuthRoleBased.Core.Dtos;
using AuthRoleBased.Core.Dtos.Auth;

namespace AuthRoleBased.Core.Interfaces
{
    public interface IAuthService
    {
        Task<ResponseDto<bool>> SeedRolesAsync();
        Task<ResponseDto<AuthSuccessfulDto<TokenDto>>> RegisterAsync(RegisterDto registerDto);
        Task<ResponseDto<AuthSuccessfulDto<TokenDto>>> LoginAsync(LoginDto loginDto);
        Task<ResponseDto<bool>> MakeAdminAsync(UpdatePermissionDto updatePermissionDto);
        Task<ResponseDto<bool>> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto);
        Task<ResponseDto<bool>> LogoutAsync();
        Task<ResponseDto<TokenDto>> RefreshTokensAsync(string refreshToken);
    }
}