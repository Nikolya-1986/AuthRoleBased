using AuthRoleBased.Core.Entities;

namespace AuthRoleBased.Core.Dtos.User
{
    public class BasicUserInformation
    {

        public string Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public IList<string> Role { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
    }
}