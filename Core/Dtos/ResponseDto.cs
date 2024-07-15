namespace AuthRoleBased.Core.Dtos
{
    public class ResponseDto<T>
    {
        public bool IsSucceed { get; set; }
        public required string Message { get; set; }
        public T Data { get; set; }
    }
}