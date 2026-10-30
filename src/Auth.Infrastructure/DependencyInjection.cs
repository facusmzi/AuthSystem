using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Persistence;
using Auth.Infrastructure.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        services.TryAddSingletonTimeProvider();

        services.AddValidatedOptions<PasswordHashingOptions>(PasswordHashingOptions.SectionName);
        services.AddValidatedOptions<PasswordPolicyOptions>(PasswordPolicyOptions.SectionName)
            .Validate(o => o.MinLength <= o.MaxLength, "PasswordPolicy:MinLength must be <= MaxLength.");
        services.AddValidatedOptions<AccountLockoutOptions>(AccountLockoutOptions.SectionName);
        services.AddValidatedOptions<SeedOptions>(SeedOptions.SectionName);

        AddDataProtection(services, configuration, environment);
        AddPersistence(services, configuration);
        AddIdentity(services);

        return services;
    }

    private static void AddDataProtection(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        var options = configuration.GetSection(KeyStorageOptions.SectionName).Get<KeyStorageOptions>() ?? new KeyStorageOptions();
        var keysPath = Path.GetFullPath(Path.Combine(environment.ContentRootPath, options.KeysPath));

        var builder = services.AddDataProtection()
            .SetApplicationName("Auth")
            .PersistKeysToFileSystem(new DirectoryInfo(keysPath));

        // En producción las claves nunca quedan en claro en disco. En Linux configurar ProtectKeysWithCertificate.
        if (OperatingSystem.IsWindows() && environment.IsProduction())
        {
            builder.ProtectKeysWithDpapi();
        }
    }

    private static void AddPersistence(IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("Default")
            ?? throw new InvalidOperationException("ConnectionStrings:Default is not configured.");

        services.AddSingleton<SqlitePragmaInterceptor>();
        services.AddDbContext<AppDbContext>((sp, options) => options
            .UseSqlite(connectionString)
            .AddInterceptors(sp.GetRequiredService<SqlitePragmaInterceptor>()));

        services.AddScoped<DbSeeder>();
    }

    private static void AddIdentity(IServiceCollection services)
    {
        services.AddIdentityCore<ApplicationUser>()
            .AddRoles<ApplicationRole>()
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders()
            .AddPasswordValidator<MaxLengthPasswordValidator>()
            .AddPasswordValidator<EmailAsPasswordValidator>();

        services.AddOptions<IdentityOptions>()
            .Configure<IOptions<PasswordPolicyOptions>, IOptions<AccountLockoutOptions>>((identity, policy, lockout) =>
            {
                identity.User.RequireUniqueEmail = true;
                identity.User.AllowedUserNameCharacters = string.Empty; // UserName = Email (validado aparte)

                // NIST SP 800-63B: solo longitud, sin reglas de composición.
                identity.Password.RequiredLength = policy.Value.MinLength;
                identity.Password.RequireDigit = false;
                identity.Password.RequireLowercase = false;
                identity.Password.RequireUppercase = false;
                identity.Password.RequireNonAlphanumeric = false;
                identity.Password.RequiredUniqueChars = 1;

                identity.Lockout.AllowedForNewUsers = true;
                identity.Lockout.MaxFailedAccessAttempts = lockout.Value.MaxFailedAttempts;
                identity.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(lockout.Value.LockoutMinutes);

                identity.ClaimsIdentity.UserIdClaimType = "sub";
                identity.ClaimsIdentity.EmailClaimType = "email";
            });

        services.AddSingleton<HashingConcurrencyLimiter>();
        services.AddScoped<IPasswordHasher<ApplicationUser>, Argon2PasswordHasher>();
    }

    internal static OptionsBuilder<T> AddValidatedOptions<T>(this IServiceCollection services, string sectionName)
        where T : class =>
        services.AddOptions<T>()
            .BindConfiguration(sectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

    private static void TryAddSingletonTimeProvider(this IServiceCollection services)
    {
        if (!services.Any(d => d.ServiceType == typeof(TimeProvider)))
        {
            services.AddSingleton(TimeProvider.System);
        }
    }
}
