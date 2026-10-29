var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();

var app = builder.Build();
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapControllers();
app.Run("http://127.0.0.1:5003");
