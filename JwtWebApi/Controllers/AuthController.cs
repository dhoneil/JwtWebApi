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

        public static User user { get; set; } = new User();

        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
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


        [HttpPost ("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] hash, out byte[] salt);
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

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName)
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
