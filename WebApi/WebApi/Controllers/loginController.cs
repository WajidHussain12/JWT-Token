using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApi.Model;


namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class loginController : ControllerBase
    {
        private IConfiguration _configuration;
        private readonly WebApiDbContext _dbContext;
        public loginController(IConfiguration configuration, WebApiDbContext dbContext)
        {
            _configuration = configuration;
            _dbContext = dbContext;
        }

        [HttpPost]
        public IActionResult Login(Login login)
        {
            if (login.name != null)
            {
                var user = login.name.ToString();
                var verifiedCredentials = verifyCredentials(user);
                return Ok(verifiedCredentials);

            }
            return Unauthorized();
        }


        private IActionResult verifyCredentials(string username)
        {
            var verifyData = _dbContext.logins.FirstOrDefault(u => u.name == username);
            var getVerifyName = verifyData?.name;

            if (getVerifyName != null)
            {
                string Token = generateToken(getVerifyName);
                return Ok(new
                {
                    username = getVerifyName,
                    Token = Token
                });
            }
            return Unauthorized();
        }



        private string generateToken(string userName)
        { 

            var claims = new[]
            {
                //new Claim(JwtRegisteredClaimNames.Sub, jwt.Subject),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
                new Claim("UserName",userName),
                new Claim(JwtRegisteredClaimNames.Exp, DateTime.UtcNow.AddMinutes(1).ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, userName),
                new Claim(JwtRegisteredClaimNames.Name, userName)

             };


            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"], _configuration["Jwt:Audience"], claims,
                expires: DateTime.Now.AddMinutes(1), signingCredentials: credentials);


            return new JwtSecurityTokenHandler().WriteToken(token);
        }





    }

}
