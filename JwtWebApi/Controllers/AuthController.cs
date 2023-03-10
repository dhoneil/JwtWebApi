using JwtWebApi.Services.UserService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration configuration;
        private readonly IUserService userService;

        public static User user { get; set; } = new User();

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            this.configuration = configuration;
            this.userService = userService;
        }

        private void CreatePasswordHash(string plainPassword,
            out byte[] passwordHash,
            out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(plainPassword));
            }
        }


        //read claims
        [HttpGet, Authorize]
        public ActionResult<object> GetMe()
        {
            var usernameFinal = userService.GetMyName();
            return Ok(usernameFinal);

            //var userName = User?.Identity?.Name;
            //var userName2 = User?.FindFirstValue(ClaimTypes.Name);
            //var role = User?.FindFirstValue(ClaimTypes.Role);
            //return Ok(new {userName, userName2, role});
        }


        [HttpPost ("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] hash, out byte[] salt);

            //in actual prod, save in db
            user.UserName = request.UserName;
            user.PasswordHash = hash;
            user.PasswordSalt= salt;
            return Ok(user);
        }

        [HttpPost ("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            //check if username is valid. (or in actual prod, check if exists in db)
            if (user.UserName != request.UserName)
            {
                return BadRequest("Username not found");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password");
            }

            //if all passed
            //create token
            string token = CreateToken(user);

            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);

            return Ok(token);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            //in actual, look in database
            if (!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Invalid Refresh Token");
            }
            else if (user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token Expired");
            }

            string token = CreateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            SetRefreshToken(newRefreshToken);

            return Ok(token);
        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires= DateTime.Now.AddDays(7),
                Created= DateTime.Now
            };
            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newrefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newrefreshToken.Expires,
            };
            Response.Cookies.Append("refreshtoken", newrefreshToken.Token, cookieOptions);

            //in actual prod, save in db
            user.RefreshToken = newrefreshToken.Token;
            user.TokenCreated = newrefreshToken.Created;
            user.TokenExpires = newrefreshToken.Expires;
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "Admin")
            };
            var key = new SymmetricSecurityKey(
                            System.Text.Encoding.UTF8.GetBytes(configuration.GetSection("Appsettings:Token").Value)
                          );
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims : claims,
                expires : DateTime.Now.AddDays(1),
                signingCredentials: cred
            );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

        private bool VerifyPasswordHash(string password, byte[] passwordhash, byte[] passwordSalt) 
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedhash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedhash.SequenceEqual(passwordhash);
            }
        }

        
    }
}
