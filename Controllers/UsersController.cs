using auth_service.Models;
using auth_service.Services;
using Microsoft.AspNetCore.Mvc;


namespace server.Controllers;

[Route("api/[controller]")]
[ApiController]
public class UsersController : ControllerBase
{

    private readonly UserServices _userServices;

    public UsersController(UserServices userServices)
    {
        _userServices = userServices;
    }

    [HttpPost("login")]
    public IActionResult Login(UserLogin loginUser)
    {
        UserVerified verifiedUser = _userServices.Login(loginUser, "nebuton");
        return Ok(verifiedUser);
    }


    [HttpPost("register")]
    public IActionResult Register(UserRegistration userReg)
    {
        bool status = _userServices.RegisterUser(userReg, "nebuton");
        return Ok(status);
    }



}