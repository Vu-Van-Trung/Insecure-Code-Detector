using UserManager;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();

var app = builder.Build();
Database.Initialize();
Console.WriteLine("Tài khoản demo: admin / admin123");

app.UseDefaultFiles();
app.UseStaticFiles();
app.MapControllers();
app.Run("http://127.0.0.1:5001");
