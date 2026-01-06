using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// --- 1. Database & Identity Setup ---
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=notes.db";
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(connectionString));

builder.Services.AddIdentityCore<IdentityUser>(options => {
    // Relaxed password settings for easier testing
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6;
})
.AddEntityFrameworkStores<AppDbContext>();

// --- 2. Authentication (JWT) Setup ---
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    var key = Encoding.UTF8.GetBytes("ThisIsASuperSecretKeyForTestingPurposes123!");
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

// --- 3. Middleware ---
app.UseFileServer(); // Serves the index.html and main.js from wwwroot
app.UseAuthentication();
app.UseAuthorization();

// --- 4. API Endpoints ---

// Register
app.MapPost("/register", async (UserManager<IdentityUser> userManager, RegisterDto dto) =>
{
    var user = new IdentityUser { UserName = dto.Email, Email = dto.Email };
    var result = await userManager.CreateAsync(user, dto.Password);
    return result.Succeeded ? Results.Ok() : Results.BadRequest(result.Errors);
});

// Login
app.MapPost("/login", async (UserManager<IdentityUser> userManager, LoginDto dto) =>
{
    var user = await userManager.FindByEmailAsync(dto.Email);
    if (user == null || !await userManager.CheckPasswordAsync(user, dto.Password))
        return Results.Unauthorized();

    var key = Encoding.UTF8.GetBytes("ThisIsASuperSecretKeyForTestingPurposes123!");
    var descriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email!)
        }),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha266Signature)
    };
    var handler = new JwtSecurityTokenHandler();
    var token = handler.WriteToken(handler.CreateToken(descriptor));

    return Results.Text(token); // Returns plain string as expected by tests
});

// Get Notes
app.MapGet("/notes", async (AppDbContext db, ClaimsPrincipal user) =>
{
    var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
    var notes = await db.Notes
        .Where(n => n.UserId == userId)
        .Select(n => new NoteDto(n.Id, n.Content))
        .ToListAsync();
    return Results.Ok(notes);
}).RequireAuthorization();

// Create Note
app.MapPost("/notes", async (AppDbContext db, ClaimsPrincipal user, CreateNoteDto dto) =>
{
    var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
    var note = new Note { Content = dto.Content, UserId = userId! };
    db.Notes.Add(note);
    await db.SaveChangesAsync();
    return Results.Created($"/notes/{note.Id}", new NoteDto(note.Id, note.Content));
}).RequireAuthorization();

// Update Note
app.MapPut("/notes/{id}", async (int id, AppDbContext db, ClaimsPrincipal user, UpdateNoteDto dto) =>
{
    if (id != dto.Id) return Results.BadRequest();
    var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
    var note = await db.Notes.FindAsync(id);

    if (note == null) return Results.NotFound();
    if (note.UserId != userId) return Results.Forbid();

    note.Content = dto.Content;
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

// Delete Note
app.MapDelete("/notes/{id}", async (int id, AppDbContext db, ClaimsPrincipal user) =>
{
    var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
    var note = await db.Notes.FindAsync(id);

    if (note == null) return Results.NotFound();
    if (note.UserId != userId) return Results.Forbid();

    db.Notes.Remove(note);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

// --- 5. Database Initialization ---
// Automatically apply migrations at startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

app.Run();

// --- Data Models & DTOs ---

public class AppDbContext : IdentityDbContext<IdentityUser>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    public DbSet<Note> Notes { get; set; }
}

public class Note
{
    public int Id { get; set; }
    public string Content { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
}

public record RegisterDto(string Email, string Password);
public record LoginDto(string Email, string Password);
public record CreateNoteDto(string Content);
public record UpdateNoteDto(int Id, string Content);
public record NoteDto(int Id, string Content);