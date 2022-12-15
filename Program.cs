using auth_service.Entities;
using auth_service.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddDbContext<NebutonDbContext>();
builder.Services.AddDbContext<HyderionDbContext>();
builder.Services.AddScoped<UserServices>();
builder.Services.AddCors(options =>
{
    options.AddPolicy(name: "MyAllowedSpecificOrigins",
        policy  =>
        {
            policy.WithOrigins("http://localhost:3000", "https://dev.hyderion.com");
        });
});
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors("MyAllowedSpecificOrigins");

app.UseAuthorization();

app.MapControllers();

app.Run();
