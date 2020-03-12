using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace JWT.Sample.Controllers
{
    [Route("api/[controller]")]
    public class JWTController : Controller
    {
        private readonly IHttpContextAccessor _accessor;

        public IHttpContextAccessor HttpContextAccessor { get; set; }

        public JWTController(IHttpContextAccessor accessor)
        {
            _accessor = accessor;
        }

        [HttpGet]
        public ActionResult<IEnumerable<string>> Get()
        {
            // 簡單創建一個token令牌

            // 創建聲明數組
            var claims = new Claim[]
           {
                new Claim(ClaimTypes.Name, "jacky"),
                new Claim(JwtRegisteredClaimNames.Email, "jacky@gmail.com"),
                new Claim(JwtRegisteredClaimNames.Sub, "1"),//主題subject，就是id uid
           };

            // 實例化 token 對象

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("jacky6632003jacky6632003"));//至少16位密鑰

            var token = new JwtSecurityToken(
                issuer: "http://localhost:5001",
                audience: "http://localhost:5002",
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            );

            // 生成token
            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            return new string[] { jwtToken };
        }

        [HttpGet]
        [Route("tokens/{jwtStr}")]
        public ActionResult<IEnumerable<string>> tokens(string jwtStr)
        {
            // 獲取token內容的方法
            //1
            var jwtHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken = jwtHandler.ReadJwtToken(jwtStr);

            //2
            var sub = User.FindFirst(d => d.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")?.Value;

            //3
            var name = _accessor.HttpContext.User.Identity.Name;
            var claims = _accessor.HttpContext.User.Claims;
            var claimTypeVal = (from item in claims
                                where item.Type == JwtRegisteredClaimNames.Email
                                select item.Value).ToList();

            return new string[] { JsonConvert.SerializeObject(jwtToken), sub, name, JsonConvert.SerializeObject(claimTypeVal) };
        }
    }
}