

using auth_service.Models;
using auth_service.Services;
using Microsoft.AspNetCore.Mvc;

namespace server.Controllers;

[Route("[controller]")]
[ApiController]
public class NebutonUsersController : ControllerBase
{

    private readonly UserServices _userServices;

    public NebutonUsersController(UserServices userServices)
    {
        _userServices = userServices;
    }

    [HttpPost("login")]
    public IActionResult Login(UserLogin loginUser)
    {
        UserVerified verifiedUser = _userServices.Login(loginUser, "nebuton");
        return Ok(verifiedUser);
        // string jwt = _userServices.GenerateNebutonJwt("iaboud308@gmail.com", "Admin");
        // return Ok(jwt);
    }


    [HttpPost("register")]
    public IActionResult Register(UserRegistration userReg)
    {
        bool status = _userServices.RegisterUser(userReg, "nebuton");
        return Ok(status);
    }



}