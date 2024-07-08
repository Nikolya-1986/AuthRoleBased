namespace AuthRoleBased.Core.Dtos
{
    public class AuthServiceResponseDto
    {
        public bool IsSucceed { get; set; }
        public required string Message { get; set; }
        public string? AccessToken { get; set;}
        public string? RefreshToken { get; set;}
    }
}