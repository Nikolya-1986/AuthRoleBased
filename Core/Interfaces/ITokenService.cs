using AuthRoleBased.Core.Dtos;
using AuthRoleBased.Core.Dtos.Auth;

namespace AuthRoleBased.Core.Interfaces
{
    public interface ITokenService
    {
        void SaveRefreshToken(RefreshToken refreshToken);
        void UpdateRefreshToken(RefreshToken refreshToken);
        RefreshToken GetStoredRefreshToken(string token);
        void RemoveRefreshToken(string token);
    }
}