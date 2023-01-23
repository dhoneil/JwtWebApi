using System.Security.Claims;

namespace JwtWebApi.Services.UserService
{
    public class UserService : IUserService
    {
        public UserService(IHttpContextAccessor httpContextAccessor)
        {
            HttpContextAccessor = httpContextAccessor;
        }

        public IHttpContextAccessor HttpContextAccessor { get; }

        public string GetMyName()
        {
            var res = string.Empty;
            if (HttpContextAccessor != null)
            {
                res = HttpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }
            return res;
        }
    }
}
