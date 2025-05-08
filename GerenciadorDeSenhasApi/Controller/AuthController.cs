using GerenciadorDeSenhasApi.Dto;
using GerenciadorDeSenhasApi.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace GerenciadorDeSenhasApi.Controller;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{

    public static User user = new();
    
    [HttpPost("register")]
    public ActionResult<User> Register(UserDto request)
    {
        var hashedPassword = new PasswordHasher<User>()
            .HashPassword(user,  request.Password);
        
        user.Username = request.Username;
        user.PasswordHash = hashedPassword;

        return Ok(user);
    }
}