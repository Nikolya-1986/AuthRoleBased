using AuthRoleBased.Core.Dtos;
using AuthRoleBased.Core.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace AuthRoleBased.Controllers
{
    [Route("auth-role-based/")]
    [ApiController]
    public class AuthController: ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // Route For Seeding my roles to DB
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seerRoles = await _authService.SeedRolesAsync();

            return Ok(seerRoles);
        }

        // Route -> Register
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var registerResult = await _authService.RegisterAsync(registerDto);

            if (registerResult.IsSucceed)
                return Ok(registerResult);

            return BadRequest(registerResult);
        }

        // Route -> Login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var loginResult = await _authService.LoginAsync(loginDto);

            if(loginResult.IsSucceed)
                return Ok(loginResult);

            return Unauthorized(loginResult);
        }

        // Route -> Logout
        [HttpPost]
        [Route("logout")]
        public async Task<IActionResult> Logout()
        {
            var loginResult = await _authService.LogoutAsync();

            if(loginResult.IsSucceed)
                return Ok(loginResult);

            return Unauthorized(loginResult);
        }

        // Route -> make user -> admin
        [HttpPost]
        [Route("make-admin")]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var operationResult = await _authService.MakeAdminAsync(updatePermissionDto);

            if(operationResult.IsSucceed)
                return Ok(operationResult);

            return BadRequest(operationResult);
        }

        // Route -> make user -> owner
        [HttpPost]
        [Route("make-owner")]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var operationResult = await _authService.MakeOwnerAsync(updatePermissionDto);

            if (operationResult.IsSucceed)
                return Ok(operationResult);

            return BadRequest(operationResult);
        }

        // Route -> update-tokens
        [HttpPost]
        [Route("update-tokens")]
        public async Task<IActionResult> UpdateTokens(string refreshToken)
        {
            var tokensResult = await _authService.UpdateTokensAsync(refreshToken);
            if (tokensResult.IsSucceed)
               return Ok(tokensResult);
            return BadRequest(tokensResult);
        }
    }
}