


using Microsoft.AspNetCore.Mvc;


[ApiController]
[Route("/")]
public class HomeController : ControllerBase {


    public HomeController() {

    }


    [HttpGet]
    public IActionResult Index() {

        return Ok(new { ServiceName = "auth-service", Status = "Active" });
    }



}