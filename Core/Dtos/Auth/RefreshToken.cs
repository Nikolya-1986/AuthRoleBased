namespace AuthRoleBased.Core.Dtos.Auth
{
    public class RefreshToken
    {
        public string Token { get; set; }
        public string Email { get; set; }
        public DateTime ExpirationDate { get; set; }
    }
}