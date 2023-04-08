using System;
namespace auth_service.Models
{
	public class UserRegistration
	{

        public UserRegistration() {

        }


        public UserRegistration(string email, string password, UserRole role) {
            this.Email = email;
            this.Password = password;
            this.UserRole = role;
            this.FirstName = "Super";
            this.LastName = "Admin";
        }



        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public UserRole UserRole { get; set; }
    }
}

