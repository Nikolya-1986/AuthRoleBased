namespace AuthRoleBased.Models.Enums
{
    public enum ResultStatus
    {
        OK = 200,

        BadRequest = 400,
        Unauthorized = 401,
        Forbidden = 403,
        NotFound = 404,
        
        InternalServerError = 500,
        BadGateway = 502
    }
}