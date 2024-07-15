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
using Microsoft.AspNetCore.Mvc;

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
        public async Task<ResponseDto<TokenDto>> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByEmailAsync(loginDto.Email);

            if (user is null)
                return new ResponseDto<TokenDto>()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials",
                    Data = new TokenDto()
                    {
                        AccessToken = null,
                        RefreshToken = null,
                    }
                };

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!isPasswordCorrect)
                return new ResponseDto<TokenDto>()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials",
                    Data = new TokenDto()
                    {
                        AccessToken = null,
                        RefreshToken = null,
                    }
                };

            var userRoles = await _userManager.GetRolesAsync(user);

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

            return new ResponseDto<TokenDto>()
            {
                IsSucceed = true,
                Message = "User Login Successfully",
                Data = new TokenDto()
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                }
            };
        }

        public async Task<ResponseDto<bool>> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return new ResponseDto<bool>()
                {
                    IsSucceed = false,
                    Message = "Invalid User name!!!!!!!!",
                    Data = false,
                };

            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            return new ResponseDto<bool>()
            {
                IsSucceed = true,
                Message = "User is now an ADMIN",
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
                    Data = false,
                };

            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);

            return new ResponseDto<bool>()
            {
                IsSucceed = true,
                Message = "User is now an OWNER",
                Data = true,
            };
        }

        public async Task<ResponseDto<bool>> RegisterAsync(RegisterDto registerDto)
        {
            var isExistsUser = await _userManager.FindByEmailAsync(registerDto.Email);

            if (isExistsUser != null)
                return new ResponseDto<bool>()
                {
                    IsSucceed = false,
                    Message = "Email Already Exists",
                    Data = false,
                };
            

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
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
                return new ResponseDto<bool>()
                {
                    IsSucceed = false,
                    Message = errorString,
                    Data = false,
                };
            }

            // Add a Default USER Role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return new ResponseDto<bool>()
            {
                IsSucceed = true,
                Message = "User Created Successfully",
                Data = true,
            };
        }

        public async Task<ResponseDto<bool>> LogoutAsync()
        {
            await _signInManager.SignOutAsync();
            return new ResponseDto<bool>()
            {
                IsSucceed = true,
                Message = "User Logout Successfuly",
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
                    Data = false,
                };
            
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));

            return new ResponseDto<bool>()
            {
                IsSucceed = true,
                Message = "Role Seeding Done Successfully",
                Data = false,
            };
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

        public string GenerateRefreshToken()
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