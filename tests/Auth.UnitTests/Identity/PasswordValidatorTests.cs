using Auth.Infrastructure.Identity;
using Auth.Infrastructure.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using MsOptions = Microsoft.Extensions.Options.Options;

namespace Auth.UnitTests.Identity;

public sealed class PasswordValidatorTests
{
    private static readonly UserManager<ApplicationUser> Manager = CreateManager();

    private static UserManager<ApplicationUser> CreateManager()
    {
        var identity = new IdentityOptions();
        identity.Password.RequiredLength = 12;
        identity.Password.RequireDigit = false;
        identity.Password.RequireLowercase = false;
        identity.Password.RequireUppercase = false;
        identity.Password.RequireNonAlphanumeric = false;
        identity.Password.RequiredUniqueChars = 1;

        return new UserManager<ApplicationUser>(
            Substitute.For<IUserStore<ApplicationUser>>(),
            MsOptions.Create(identity),
            Substitute.For<IPasswordHasher<ApplicationUser>>(),
            [],
            [new PasswordValidator<ApplicationUser>(), new MaxLengthPasswordValidator(MsOptions.Create(new PasswordPolicyOptions())), new EmailAsPasswordValidator()],
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            Substitute.For<IServiceProvider>(),
            NullLogger<UserManager<ApplicationUser>>.Instance);
    }

    private static async Task<IReadOnlyList<string>> ErrorsFor(string password, string email = "someone@example.com")
    {
        var user = new ApplicationUser { Email = email, UserName = email };
        var codes = new List<string>();
        foreach (var validator in Manager.PasswordValidators)
        {
            var result = await validator.ValidateAsync(Manager, user, password);
            codes.AddRange(result.Errors.Select(e => e.Code));
        }
        return codes;
    }

    [Fact]
    public async Task Rejects_passwords_shorter_than_minimum()
    {
        (await ErrorsFor("short-pass1")).ShouldContain("PasswordTooShort");
    }

    [Fact]
    public async Task Accepts_minimum_length_without_composition_rules()
    {
        (await ErrorsFor("alllowercaseletters")).ShouldBeEmpty();
        (await ErrorsFor("123456789012")).ShouldBeEmpty();
    }

    [Fact]
    public async Task Rejects_passwords_longer_than_maximum()
    {
        (await ErrorsFor(new string('a', 129))).ShouldContain(MaxLengthPasswordValidator.Code);
        (await ErrorsFor(new string('a', 128))).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("someone@example.com")]
    [InlineData("SOMEONE@EXAMPLE.COM")]
    [InlineData("someone")]
    public async Task Rejects_password_equal_to_email(string password)
    {
        var errors = await ErrorsFor(password, "someone@example.com");
        errors.ShouldContain(EmailAsPasswordValidator.Code);
    }
}
