using System;
namespace auth_service.Entities
{
    public class HyderionUser
    {
        public HyderionUser()
        {

        }

        public HyderionUser(string firstName, string lastName, string email, string hashedPassword, UserRole userRole)
        {
            this.FirstName = firstName;
            this.LastName = lastName;
            this.Email = email;
            this.HashedPassword = hashedPassword;
            this.UserRole = userRole.ToString();
        }


        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string HashedPassword { get; set; }
        public string UserRole { get; set; }
    }
}

