using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthRoleBased.Core.Dtos;
using AuthRoleBased.Core.Dtos.OtherObjects;
using AuthRoleBased.Core.Entities;
using AuthRoleBased.Core.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using AuthRoleBased.Models.Enums;
using AuthRoleBased.Core.Dtos.Auth;

namespace AuthRoleBased.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = configuration; 
        }
        public async Task<ResponseDto<AuthSuccessfulDto<TokenDto>>> LoginAsync(LoginDto loginDto)
        {
            try {
                var user = await _userManager.FindByEmailAsync(loginDto.Email);

                if (user is null)
                    return new ResponseDto<AuthSuccessfulDto<TokenDto>>()
                    {
                        IsSucceed = false,
                        Message = "Invalid Credentials (User doesn't exist)",
                        Status = ResultStatus.Unauthorized,
                        Data = new AuthSuccessfulDto<TokenDto>(),
                    };

                var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);

                if (!isPasswordCorrect)
                    return new ResponseDto<AuthSuccessfulDto<TokenDto>>()
                    {
                        IsSucceed = false,
                        Message = "Invalid Credentials (Inncorect password)",
                        Status = ResultStatus.Unauthorized,
                        Data = new AuthSuccessfulDto<TokenDto>(),
                    };

                IList<string> userRole = await _userManager.GetRolesAsync(user);
                var (accessToken, refreshToken) = GetPairTokens(userRole, user);

                return new ResponseDto<AuthSuccessfulDto<TokenDto>>()
                {
                    IsSucceed = true,
                    Message = "User Login Successfully",
                    Status = ResultStatus.OK,
                    Data = new AuthSuccessfulDto<TokenDto>()
                    {
                        Id = user.Id,
                        FirstName = user.FirstName,
                        LastName = user.LastName,
                        UserName = user.UserName,
                        Role = userRole,
                        Email = user.Email,
                        Tokens = new TokenDto()
                        {
                            AccessToken = accessToken,
                            RefreshToken = refreshToken,
                        }
                    }
                };
            }
            catch (Exception ex)
            {
                return new ResponseDto<AuthSuccessfulDto<TokenDto>>()
                {
                    IsSucceed = true,
                    Message = ex.Message,
                    Status = ResultStatus.InternalServerError,
                    Data = new AuthSuccessfulDto<TokenDto>(),
                };
            }
        }

        public async Task<ResponseDto<bool>> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return new ResponseDto<bool>()
                {
                    IsSucceed = false,
                    Message = "Invalid User name!!!!!!!!",
                    Status = ResultStatus.OK,
                    Data = false,
                };

            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            return new ResponseDto<bool>()
            {
                IsSucceed = true,
                Message = "User is now an ADMIN",
                Status = ResultStatus.OK,
                Data = true,
            };
        }

        public async Task<ResponseDto<bool>> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return new ResponseDto<bool>()
                {
                    IsSucceed = false,
                    Message = "Invalid User name!!!!!!!!",
                    Status = ResultStatus.BadRequest,
                    Data = false,
                };

            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);

            return new ResponseDto<bool>()
            {
                IsSucceed = true,
                Message = "User is now an OWNER",
                Status = ResultStatus.OK,
                Data = true,
            };
        }

        public async Task<ResponseDto<AuthSuccessfulDto<TokenDto>>> RegisterAsync(RegisterDto registerDto)
        {
            var isExistsUser = await _userManager.FindByEmailAsync(registerDto.Email);

            if (isExistsUser != null)
                return new ResponseDto<AuthSuccessfulDto<TokenDto>>()
                {
                    IsSucceed = false,
                    Message = "Email Already Exists",
                    Status = ResultStatus.BadRequest,
                    Data = new AuthSuccessfulDto<TokenDto>(),
                };
            
            ApplicationUser newUser = new ApplicationUser()
            {
                Id = Guid.NewGuid().ToString(),
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                Role = StaticUserRoles.USER,
                Email = registerDto.Email,
                UserName = registerDto.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var createUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed Beacause: ";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += " # " + error.Description;
                }
                return new ResponseDto<AuthSuccessfulDto<TokenDto>>()
                {
                    IsSucceed = false,
                    Message = errorString,
                    Status = ResultStatus.BadRequest,
                    Data = new AuthSuccessfulDto<TokenDto>(),
                };
            }

            // Add a Default USER Role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            var userRoles = await _userManager.GetRolesAsync(newUser);
            var (accessToken, refreshToken) = GetPairTokens(userRoles, newUser);

            return new ResponseDto<AuthSuccessfulDto<TokenDto>>()
            {
                IsSucceed = true,
                Message = "User Created Successfully",
                Status = ResultStatus.OK,
                Data = new AuthSuccessfulDto<TokenDto>()
                {
                    Id = Guid.NewGuid().ToString(),
                    FirstName = registerDto.FirstName,
                    LastName = registerDto.LastName,
                    Role = [StaticUserRoles.USER],
                    Email = registerDto.Email,
                    UserName = registerDto.UserName,
                    Tokens = new TokenDto()
                    {
                        AccessToken = accessToken,
                        RefreshToken = refreshToken,
                    }
                }
            };
        }

        public async Task<ResponseDto<bool>> LogoutAsync()
        {
            await _signInManager.SignOutAsync();
            return new ResponseDto<bool>()
            {
                IsSucceed = true,
                Message = "User Logout Successfuly",
                Status = ResultStatus.OK,
                Data = true,
            };
        }

        public async Task<ResponseDto<bool>> SeedRolesAsync()
        {
            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
                return new ResponseDto<bool>()
                {
                    IsSucceed = true,
                    Message = "Roles Seeding is Already Done",
                    Status = ResultStatus.BadRequest,
                    Data = false,
                };
            
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));

            return new ResponseDto<bool>()
            {
                IsSucceed = true,
                Message = "Role Seeding Done Successfully",
                Status = ResultStatus.OK,
                Data = false,
            };
        }

        private (string accessToken, string refreshToken) GetPairTokens(IList<string> userRoles, ApplicationUser user)
        {
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString()),
                new Claim("FirstName", user.FirstName),
                new Claim("LastName", user.LastName),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var accessToken = GenerateAccessToken(authClaims);
            var refreshToken = GenerateRefreshToken();
            return (accessToken, refreshToken);
        }

        private string GenerateAccessToken(List<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(1),
                    claims: claims,
                    signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[486];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }
}