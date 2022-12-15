

using auth_service.Models;
using auth_service.Services;
using Microsoft.AspNetCore.Mvc;

namespace server.Controllers;

[Route("[controller]")]
[ApiController]
public class HyderionUsersController : ControllerBase
{

    private readonly UserServices _userServices;

    public HyderionUsersController(UserServices userServices)
    {
        _userServices = userServices;
    }

    [HttpPost("login")]
    public IActionResult Login(UserLogin loginUser)
    {
        UserVerified verifiedUser = _userServices.Login(loginUser, "hyderion");
        return Ok(verifiedUser);
    }


    [HttpPost("register")]
    public IActionResult Register(UserRegistration userReg)
    {
        bool status = _userServices.RegisterUser(userReg, "hyderion");
        return Ok(status);
    }



}