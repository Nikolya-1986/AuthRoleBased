namespace AuthRoleBased.Core.Dtos
{
    public class AuthServiceResponseDto
    {
        public bool IsSucceed { get; set; }
        public required string Message { get; set; }
    }
}