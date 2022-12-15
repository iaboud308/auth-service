using System;
using auth_service.Entities;

namespace auth_service.Models
{
	public class UserVerified
	{

        public UserVerified()
        {

        }


		public UserVerified(User user, string jwt)
		{
            this.Id = user.Id;
            this.FirstName = user.FirstName;
            this.LastName = user.LastName;
            this.Email = user.Email;
            this.UserRole = user.UserRole;
            this.Jwt = jwt;
        }


        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string UserRole { get; set; }
        public string Jwt { get; set; }


    }
}

