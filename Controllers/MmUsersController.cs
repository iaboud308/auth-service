



using auth_service.Models;
using auth_service.Services;
using Microsoft.AspNetCore.Mvc;




[ApiController]
[Route("[controller]")]
public class MmUsersController : ControllerBase {
    private readonly UserServices _userServices;


    public MmUsersController(UserServices userServices) {
        _userServices = userServices;

    }


    [HttpPost("login")]
    public IActionResult Login(UserLogin loginUser) {
        
        UserVerified verifiedUser = _userServices.Login(loginUser, "mm");
        return Ok(verifiedUser);
    }



    [HttpGet("register")]
    public IActionResult Register() {

        UserRegistration adminUser = new UserRegistration("mm-admin", "123456", UserRole.Admin);
        _userServices.RegisterUser(adminUser, "mm");

        return Ok("Admin user registered");
    }




}