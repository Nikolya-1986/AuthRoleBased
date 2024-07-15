using AuthRoleBased.Core.Dtos;

namespace AuthRoleBased.Core.Interfaces
{
    public interface IAuthService
    {
        Task<ResponseDto<bool>> SeedRolesAsync();
        Task<ResponseDto<bool>> RegisterAsync(RegisterDto registerDto);
        Task<ResponseDto<TokenDto>> LoginAsync(LoginDto loginDto);
        Task<ResponseDto<bool>> MakeAdminAsync(UpdatePermissionDto updatePermissionDto);
        Task<ResponseDto<bool>> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto);
        Task<ResponseDto<bool>> LogoutAsync();
    }
}