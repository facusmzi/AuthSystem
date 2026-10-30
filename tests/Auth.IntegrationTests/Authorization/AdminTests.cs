using System.Net;
using System.Net.Http.Json;
using Auth.IntegrationTests.Infrastructure;
using static Auth.IntegrationTests.Infrastructure.ApiTestExtensions;

namespace Auth.IntegrationTests.Authorization;

public sealed class AdminTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private readonly HttpClient _client = factory.CreateHttpsClient();

    [Fact]
    public async Task User_without_permission_gets_403_and_admin_gets_200()
    {
        var user = await factory.CreateUserAndLoginAsync(_client);
        var admin = await factory.CreateAdminAsync(_client);

        await (await factory.BearerClient(user.AccessToken).GetAsync("/api/v1/admin/users")).ShouldBeProblemAsync(HttpStatusCode.Forbidden, "FORBIDDEN");

        var response = await factory.BearerClient(admin.AccessToken).GetAsync($"/api/v1/admin/users?search={user.Email[..12]}");
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var page = await response.ReadJsonAsync();
        page.GetProperty("total").GetInt32().ShouldBe(1);
        page.GetProperty("items")[0].GetProperty("email").GetString().ShouldBe(user.Email);
    }

    [Fact]
    public async Task Me_lists_admin_permissions()
    {
        var admin = await factory.CreateAdminAsync(_client);

        var me = await (await factory.BearerClient(admin.AccessToken).GetAsync("/api/v1/account/me")).ReadJsonAsync();

        me.GetProperty("roles").EnumerateArray().Select(r => r.GetString()).ShouldBe(["Admin", "User"], ignoreOrder: true);
        me.GetProperty("permissions").EnumerateArray().Select(p => p.GetString()).ShouldContain("audit.read");
    }

    [Fact]
    public async Task Role_and_permission_changes_apply_without_logging_in_again()
    {
        var admin = factory.BearerClient((await factory.CreateAdminAsync(_client)).AccessToken);
        var user = await factory.CreateUserAndLoginAsync(_client);
        var userClient = factory.BearerClient(user.AccessToken);
        var roleName = $"Auditor-{Guid.NewGuid():N}"[..20];

        var created = await admin.PostAsJsonAsync("/api/v1/admin/roles", new { name = roleName, description = "Reads audit", permissions = new[] { "audit.read" } });
        created.StatusCode.ShouldBe(HttpStatusCode.Created);
        var roleId = (await created.ReadJsonAsync()).GetProperty("id").GetGuid();

        (await userClient.GetAsync("/api/v1/admin/audit")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        (await admin.PutAsJsonAsync($"/api/v1/admin/users/{user.UserId}/roles", new { roles = new[] { "User", roleName } })).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await userClient.GetAsync("/api/v1/admin/audit")).StatusCode.ShouldBe(HttpStatusCode.OK);

        (await admin.PutAsJsonAsync($"/api/v1/admin/roles/{roleId}", new { name = roleName, description = "Nothing", permissions = Array.Empty<string>() })).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await userClient.GetAsync("/api/v1/admin/audit")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        (await admin.DeleteAsync($"/api/v1/admin/roles/{roleId}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await admin.GetAsync($"/api/v1/admin/roles/{roleId}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Locking_a_user_revokes_sessions_and_blocks_login_until_unlocked()
    {
        var admin = factory.BearerClient((await factory.CreateAdminAsync(_client)).AccessToken);
        var user = await factory.CreateUserAndLoginAsync(_client);

        (await admin.PostAsync($"/api/v1/admin/users/{user.UserId}/lock", null)).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        await (await factory.BearerClient(user.AccessToken).GetAsync("/api/v1/account/me")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");
        await (await _client.RefreshAsync(user.RefreshToken)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "REFRESH_INVALID");
        await (await _client.LoginAsync(user.Email)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "INVALID_CREDENTIALS");
        var dto = await (await admin.GetAsync($"/api/v1/admin/users/{user.UserId}")).ReadJsonAsync();
        dto.GetProperty("locked").GetBoolean().ShouldBeTrue();

        factory.Clock.Advance(TimeSpan.FromMinutes(5)); // el bloqueo de admin no vence como el lockout por fallos
        await (await _client.LoginAsync(user.Email)).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "INVALID_CREDENTIALS");

        (await admin.PostAsync($"/api/v1/admin/users/{user.UserId}/unlock", null)).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await _client.LoginAsync(user.Email)).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Admin_cannot_lock_themselves()
    {
        var admin = await factory.CreateAdminAsync(_client);

        await (await factory.BearerClient(admin.AccessToken).PostAsync($"/api/v1/admin/users/{admin.UserId}/lock", null))
            .ShouldBeProblemAsync(HttpStatusCode.Conflict, "CONFLICT");
    }

    [Fact]
    public async Task System_roles_are_protected()
    {
        var admin = factory.BearerClient((await factory.CreateAdminAsync(_client)).AccessToken);
        var roles = (await (await admin.GetAsync("/api/v1/admin/roles")).ReadJsonAsync()).EnumerateArray().ToList();
        var adminRole = roles.Single(r => r.GetProperty("name").GetString() == "Admin").GetProperty("id").GetGuid();
        var userRole = roles.Single(r => r.GetProperty("name").GetString() == "User").GetProperty("id").GetGuid();

        await (await admin.DeleteAsync($"/api/v1/admin/roles/{adminRole}")).ShouldBeProblemAsync(HttpStatusCode.Conflict, "CONFLICT");
        await (await admin.PutAsJsonAsync($"/api/v1/admin/roles/{userRole}", new { name = "Member", permissions = Array.Empty<string>() }))
            .ShouldBeProblemAsync(HttpStatusCode.Conflict, "CONFLICT");
        await (await admin.PutAsJsonAsync($"/api/v1/admin/roles/{adminRole}", new { name = "Admin", permissions = new[] { "users.read" } }))
            .ShouldBeProblemAsync(HttpStatusCode.Conflict, "CONFLICT");
    }

    [Fact]
    public async Task Role_validation_rejects_unknown_permissions_and_duplicates()
    {
        var admin = factory.BearerClient((await factory.CreateAdminAsync(_client)).AccessToken);

        await (await admin.PostAsJsonAsync("/api/v1/admin/roles", new { name = "Bad", permissions = new[] { "rockets.launch" } }))
            .ShouldBeProblemAsync(HttpStatusCode.UnprocessableEntity, "VALIDATION_FAILED");
        await (await admin.PostAsJsonAsync("/api/v1/admin/roles", new { name = "admin", permissions = Array.Empty<string>() }))
            .ShouldBeProblemAsync(HttpStatusCode.Conflict, "CONFLICT");
        await (await admin.PutAsJsonAsync($"/api/v1/admin/users/{Guid.NewGuid()}/roles", new { roles = new[] { "User" } }))
            .ShouldBeProblemAsync(HttpStatusCode.NotFound, "NOT_FOUND");
    }

    [Fact]
    public async Task Admin_can_list_and_revoke_any_users_sessions()
    {
        var admin = factory.BearerClient((await factory.CreateAdminAsync(_client)).AccessToken);
        var user = await factory.CreateUserAndLoginAsync(_client);

        var sessions = (await (await admin.GetAsync($"/api/v1/admin/users/{user.UserId}/sessions")).ReadJsonAsync()).EnumerateArray().ToList();
        var sessionId = sessions.ShouldHaveSingleItem().GetProperty("id").GetGuid();

        (await admin.DeleteAsync($"/api/v1/admin/sessions/{sessionId}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        await (await factory.BearerClient(user.AccessToken).GetAsync("/api/v1/account/me")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "SESSION_REVOKED");
        await (await admin.DeleteAsync($"/api/v1/admin/sessions/{sessionId}")).ShouldBeProblemAsync(HttpStatusCode.NotFound, "NOT_FOUND");
    }

    [Fact]
    public async Task Audit_can_be_filtered_by_user_and_type()
    {
        var admin = factory.BearerClient((await factory.CreateAdminAsync(_client)).AccessToken);
        var user = await factory.CreateUserAndLoginAsync(_client);

        var response = await admin.GetAsync($"/api/v1/admin/audit?userId={user.UserId}&type=LoginSucceeded");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var items = (await response.ReadJsonAsync()).GetProperty("items").EnumerateArray().ToList();
        items.ShouldHaveSingleItem().GetProperty("type").GetString().ShouldBe("LoginSucceeded");

        await (await admin.GetAsync("/api/v1/admin/audit?type=NotAType")).ShouldBeProblemAsync(HttpStatusCode.UnprocessableEntity, "VALIDATION_FAILED");
    }

    [Fact]
    public async Task Fallback_policy_protects_endpoints_without_attributes()
    {
        // AccountController.Sessions no tiene [Authorize]: lo protege la fallback policy.
        await (await _client.GetAsync("/api/v1/account/sessions")).ShouldBeProblemAsync(HttpStatusCode.Unauthorized, "AUTH_HEADER_MISSING");
    }
}

/// <summary>Base de datos propia: el conteo de administradores no debe depender de otros tests.</summary>
public sealed class LastAdminTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    [Fact]
    public async Task The_last_admin_cannot_lose_the_admin_role()
    {
        var client = factory.CreateHttpsClient();
        var admin = await factory.CreateAdminAsync(client);
        var bearer = factory.BearerClient(admin.AccessToken);

        await (await bearer.PutAsJsonAsync($"/api/v1/admin/users/{admin.UserId}/roles", new { roles = new[] { "User" } }))
            .ShouldBeProblemAsync(HttpStatusCode.Conflict, "CONFLICT");

        var second = await factory.CreateAdminAsync(client);
        (await bearer.PutAsJsonAsync($"/api/v1/admin/users/{second.UserId}/roles", new { roles = new[] { "User" } }))
            .StatusCode.ShouldBe(HttpStatusCode.OK);
        (await factory.BearerClient(second.AccessToken).GetAsync("/api/v1/admin/users")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }
}
