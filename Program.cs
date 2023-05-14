using auth_service.Entities;
using auth_service.Services;
using Microsoft.AspNetCore.HttpLogging;
using Serilog;
using Serilog.Formatting.Compact;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("/logs/logs.txt")
    .CreateLogger();


Log.Information("Starting up");



try {

    var builder = WebApplication.CreateBuilder(args);

    builder.Logging.AddSerilog();
    builder.Host.UseSerilog((context, config) => {
        config.WriteTo.Console();
        config.Enrich.FromLogContext();
        config.WriteTo.File(formatter: new CompactJsonFormatter(), "./logs/logs.json", rollingInterval: RollingInterval.Day);
    });

    // Add services to the container.

    builder.Services.AddControllers();
    builder.Services.AddDbContext<NebutonDbContext>();
    builder.Services.AddDbContext<HyderionDbContext>();
    builder.Services.AddDbContext<MmDbContext>();
    builder.Services.AddScoped<UserServices>();
    builder.Services.AddHttpLogging(httpLogging => {
        httpLogging.LoggingFields = HttpLoggingFields.All;
    });
    builder.Services.AddCors(options =>
    {
        options.AddPolicy(name: "MyAllowedSpecificOrigins",
            policy  =>
            {
                policy.WithOrigins("http://localhost:3000", "https://dev.hyderion.com", "https://auth-demo.hyderion.com");
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

    app.UseHttpLogging();

    app.UseHttpsRedirection();

    app.UseCors("MyAllowedSpecificOrigins");

    app.UseAuthorization();

    app.MapControllers();

    app.Run();



} catch (Exception ex) {

    Log.Fatal(ex, "Unhandled Exception");

}

finally {
    Log.Information("Shut down complete");
    Log.CloseAndFlush();
}




