using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthRoleBased.Core.DBContext;
using AuthRoleBased.Core.Dtos;
using AuthRoleBased.Core.Dtos.Auth;
using AuthRoleBased.Core.Interfaces;

namespace AuthRoleBased.Core.Services
{
    public class RefreshTokenService : ITokenService
    {
        private readonly DbContextApplication _dbContextApplication;

        public RefreshTokenService(DbContextApplication dbContextApplication)
        {
            _dbContextApplication = dbContextApplication;
        }

        public RefreshToken GetStoredRefreshToken(string refreshToken)
        {
            return _dbContextApplication.RefreshTokens.SingleOrDefault(item => item.Token == refreshToken);
        }

        public void RemoveRefreshToken(string token)
        {
            var refreshToken = GetStoredRefreshToken(token);
            if (refreshToken == null)
            {
                _dbContextApplication.RefreshTokens.Remove(refreshToken);
            }
        }

        public void SaveRefreshToken(RefreshToken refreshToken)
        {
            _dbContextApplication.RefreshTokens.Add(refreshToken);
            _dbContextApplication.SaveChanges();
        }

        public void UpdateRefreshToken(RefreshToken refreshToken)
        {
            _dbContextApplication.RefreshTokens.Update(refreshToken);
            _dbContextApplication.SaveChanges();
        }
    }
}