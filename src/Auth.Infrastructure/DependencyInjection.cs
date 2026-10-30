using Auth.Application.Abstractions;
using Auth.Infrastructure.Caching;
using Auth.Infrastructure.Email;
using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Persistence;
using Auth.Infrastructure.Security;
using Auth.Infrastructure.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;

namespace Auth.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        services.TryAddSingletonTimeProvider();
        services.AddMemoryCache();
        services.AddSingleton<TimedCache>();

        AddOptions(services);
        AddDataProtection(services, configuration, environment);
        AddPersistence(services, configuration);
        AddIdentity(services);
        AddEmail(services);
        AddPasswordBreachChecker(services);

        services.AddScoped<IAuditLogger, AuditLogger>();
        services.AddScoped<IPasswordService, PasswordService>();
        services.AddScoped<IAuthService, AuthService>();

        return services;
    }

    private static void AddOptions(IServiceCollection services)
    {
        services.AddValidatedOptions<PasswordHashingOptions>(PasswordHashingOptions.SectionName);
        services.AddValidatedOptions<PasswordPolicyOptions>(PasswordPolicyOptions.SectionName)
            .Validate(o => o.MinLength <= o.MaxLength, "PasswordPolicy:MinLength must be <= MaxLength.");
        services.AddValidatedOptions<AccountLockoutOptions>(AccountLockoutOptions.SectionName);
        services.AddValidatedOptions<HibpOptions>(HibpOptions.SectionName);
        services.AddValidatedOptions<MfaOptions>(MfaOptions.SectionName);
        services.AddValidatedOptions<EmailTokenOptions>(EmailTokenOptions.SectionName);
        services.AddValidatedOptions<FrontendOptions>(FrontendOptions.SectionName);
        services.AddValidatedOptions<FeatureOptions>(FeatureOptions.SectionName);
        services.AddValidatedOptions<EmailOptions>(EmailOptions.SectionName)
            .Validate(o => o.Provider != "Smtp" || !string.IsNullOrWhiteSpace(o.Smtp.Host), "Email:Smtp:Host is required when Email:Provider is Smtp.");
        services.AddValidatedOptions<AuditOptions>(AuditOptions.SectionName);
        services.AddValidatedOptions<MaintenanceOptions>(MaintenanceOptions.SectionName);
        services.AddValidatedOptions<SeedOptions>(SeedOptions.SectionName);
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

        void Configure(IServiceProvider sp, DbContextOptionsBuilder options) => options
            .UseSqlite(connectionString)
            .AddInterceptors(sp.GetRequiredService<SqlitePragmaInterceptor>());

        // Contexto scoped para el flujo normal + factory para escrituras aisladas (auditoría, background).
        services.AddDbContext<AppDbContext>(Configure, ServiceLifetime.Scoped, ServiceLifetime.Singleton);
        services.AddDbContextFactory<AppDbContext>(Configure);

        services.AddScoped<DbSeeder>();
    }

    private static void AddIdentity(IServiceCollection services)
    {
        services.AddIdentityCore<ApplicationUser>()
            .AddRoles<ApplicationRole>()
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders()
            .AddTokenProvider<LongLivedEmailConfirmationTokenProvider>(LongLivedEmailConfirmationTokenProvider.ProviderName)
            .AddTokenProvider<PasswordResetTokenProvider>(PasswordResetTokenProvider.ProviderName)
            .AddPasswordValidator<MaxLengthPasswordValidator>()
            .AddPasswordValidator<EmailAsPasswordValidator>()
            .AddPasswordValidator<BreachedPasswordValidator>();

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

                identity.Tokens.EmailConfirmationTokenProvider = LongLivedEmailConfirmationTokenProvider.ProviderName;
                identity.Tokens.PasswordResetTokenProvider = PasswordResetTokenProvider.ProviderName;
            });

        services.AddSingleton<HashingConcurrencyLimiter>();
        services.AddSingleton<IPasswordHasher<ApplicationUser>, Argon2PasswordHasher>();
        services.AddSingleton<DummyPasswordHash>();
    }

    private static void AddEmail(IServiceCollection services)
    {
        services.AddSingleton<EmailTemplates>();
        services.AddSingleton<EmailQueue>();
        services.AddSingleton<IEmailSender, QueuedEmailSender>();
        services.AddHostedService<EmailDispatcher>();
        services.AddSingleton<IEmailTransport>(sp => sp.GetRequiredService<IOptions<EmailOptions>>().Value.Provider switch
        {
            "Smtp" => ActivatorUtilities.CreateInstance<SmtpEmailTransport>(sp),
            "Pickup" => ActivatorUtilities.CreateInstance<PickupEmailTransport>(sp),
            _ => ActivatorUtilities.CreateInstance<LoggingEmailTransport>(sp),
        });
    }

    private static void AddPasswordBreachChecker(IServiceCollection services)
    {
        var resilience = services.AddHttpClient<IPasswordBreachChecker, HibpPasswordBreachChecker>((sp, client) =>
            {
                var options = sp.GetRequiredService<IOptions<HibpOptions>>().Value;
                client.BaseAddress = new Uri(options.BaseUrl);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Auth-Service/1.0");
            })
            .AddStandardResilienceHandler();

        services.AddOptions<HttpStandardResilienceOptions>(resilience.PipelineName)
            .Configure<IOptions<HibpOptions>>((r, hibp) =>
            {
                var timeout = TimeSpan.FromSeconds(hibp.Value.TimeoutSeconds);
                r.TotalRequestTimeout.Timeout = timeout;
                r.AttemptTimeout.Timeout = timeout;
                r.Retry.MaxRetryAttempts = 1;
                r.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(Math.Max(30, timeout.TotalSeconds * 2));
            });
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
