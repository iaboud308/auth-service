using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using auth_service.Entities;
using auth_service.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog.Core;

namespace auth_service.Services
{
	public class UserServices
	{
        private readonly ILogger<UserServices> _logger;
        private readonly NebutonDbContext _nebutonContext;
		private readonly HyderionDbContext _hyderionContext;
        private readonly MmDbContext _mmDbContext;


        public UserServices(ILogger<UserServices> logger, 
                            NebutonDbContext nebutonDbContext, 
                            HyderionDbContext hyderionDbContext, 
                            MmDbContext mmDbContext)
		{
            _logger = logger;
			_nebutonContext = nebutonDbContext;
			_hyderionContext = hyderionDbContext;
            _mmDbContext = mmDbContext;
		}



		public bool RegisterUser(UserRegistration user, string context)
		{
            bool userExists = UserExist(user.Email, context);


            if (userExists)
            {
                _logger.LogInformation("User exists");
                return false;
            }


            _logger.LogInformation("User doesn't exist");


            string hashedPassword = HashPassword(user.Password);
            User newUser = new User(user.FirstName, user.LastName, user.Email, hashedPassword, user.UserRole);

            
            _logger.LogInformation("User details: {@user}", user);


            if (context.Equals("nebuton"))
            {
                _nebutonContext.Users.Add(newUser);
                _nebutonContext.SaveChanges();
            }

            if (context.Equals("hyderion"))
            {
                _hyderionContext.Users.Add(newUser);
                _hyderionContext.SaveChanges();
            }

            if (context.Equals("mm"))
            {
                
                _mmDbContext.Users.Add(newUser);
                _mmDbContext.SaveChanges();
            }

            return true;

        }



		public string HashPassword(string password)
		{
            // Add SALT
            SHA512 hash = SHA512.Create();
            byte[] passwordBytes = Encoding.Default.GetBytes(password);
            byte[] hashedPassword = hash.ComputeHash(passwordBytes);
            return Convert.ToHexString(hashedPassword);
        }


        public bool UserExist(string email, string context)
        {
            if (context.Equals("nebuton"))
            {
                return _nebutonContext.Users.Any(u => u.Email == email);
            }

            if (context.Equals("hyderion"))
            {
                return _hyderionContext.Users.Any(u => u.Email == email);
            }

             if (context.Equals("mm"))
            {
                return _mmDbContext.Users.Any(u => u.Email == email);
            }

            return true;
        }


        public User GetUserByEmail(string email, string context)
        {
            if (context.Equals("nebuton"))
            {
                return _nebutonContext.Users.FirstOrDefault(u => u.Email == email);
                // Find out what happens if user doesn't exist
            }

            if (context.Equals("hyderion"))
            {
                return _hyderionContext.Users.FirstOrDefault(u => u.Email == email);
            }

            if (context.Equals("mm"))
            {
                return _mmDbContext.Users.FirstOrDefault(u => u.Email == email);
            }

            User user = new User();
            user.Email = email;
            user.FirstName = "Invalid";
            user.LastName = "User";

            return user;

        }




        public bool ConfirmPassword(string loginPassword, string hashedPassword)
        {
            loginPassword = HashPassword(loginPassword);


            if (loginPassword.SequenceEqual(hashedPassword))
            {
                return true;
            }

            return false;
        }



        public string GenerateNebutonJwt(string email, string role)
        {


            byte[] keyBytes = Encoding.UTF8.GetBytes(AppConfig.NebutonJwtSecurityKey());
            SymmetricSecurityKey key = new SymmetricSecurityKey(keyBytes);
            SigningCredentials creds = new SigningCredentials(key, algorithm: SecurityAlgorithms.HmacSha512);
            List<Claim> claims = new List<Claim>
        {
            new Claim(ClaimTypes.Email, email),
            new Claim(ClaimTypes.Role, role)
        };

            JwtSecurityToken token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
                );

            string jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;

        }



        public string GenerateHyderionJwt(string email, string role)
        {


            byte[] keyBytes = Encoding.UTF8.GetBytes(AppConfig.HyderionJwtSecurityKey());
            SymmetricSecurityKey key = new SymmetricSecurityKey(keyBytes);
            SigningCredentials creds = new SigningCredentials(key, algorithm: SecurityAlgorithms.HmacSha512);
            List<Claim> claims = new List<Claim>
        {
            new Claim(ClaimTypes.Email, email),
            new Claim(ClaimTypes.Role, role)
        };

            JwtSecurityToken token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
                );

            string jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;

        }


          public string GenerateMmJwt(string email, string role)
        {


            byte[] keyBytes = Encoding.UTF8.GetBytes(AppConfig.MMJwtSecurityKey());
            SymmetricSecurityKey key = new SymmetricSecurityKey(keyBytes);
            SigningCredentials creds = new SigningCredentials(key, algorithm: SecurityAlgorithms.HmacSha512);
            List<Claim> claims = new List<Claim>
        {
            new Claim(ClaimTypes.Email, email),
            new Claim(ClaimTypes.Role, role)
        };

            JwtSecurityToken token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
                );

            string jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;

        }




        public UserVerified Login(UserLogin userLogin, string context)
        {
            bool userExists = UserExist(userLogin.Email, context);

            if (!userExists)
            {
                _logger.LogError("User doesn't exist");
                return null;
            }

            User user = GetUserByEmail(userLogin.Email, context);
            bool correctPassword = ConfirmPassword(userLogin.Password, user.HashedPassword);

            if (!correctPassword)
            {
                _logger.LogError("Incorrect password");
                return null;
            }

            string jwt = "";


            if (context.Equals("nebuton"))
            {
                _logger.LogInformation("User: {@email}, Context: {@context}", user.Email, context);
                jwt = GenerateNebutonJwt(user.Email, user.UserRole);

            }

            if (context.Equals("hyderion"))
            {
                _logger.LogInformation("User: {@email}, Context: {@context}", user.Email, context);
                jwt = GenerateHyderionJwt(user.Email, user.UserRole);

            }
            if (context.Equals("mm"))
            {
                _logger.LogInformation("User: {@email}, Context: {@context}", user.Email, context);
                jwt = GenerateMmJwt(user.Email, user.UserRole);

            }

            UserVerified verifiedUser = new UserVerified(user, jwt);

            return verifiedUser;


        }



    }
}

