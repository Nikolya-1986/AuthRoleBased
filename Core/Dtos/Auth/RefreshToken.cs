namespace AuthRoleBased.Core.Dtos.Auth
{
    public class RefreshToken
    {
        public string Id { get; set; }
        public string Token { get; set; }
        public string UserName { get; set; }
        public DateTime ExpirationDate { get; set; }
    }
}