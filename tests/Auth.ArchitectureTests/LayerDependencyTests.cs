using System.Reflection;
using NetArchTest.Rules;

namespace Auth.ArchitectureTests;

public sealed class LayerDependencyTests
{
    private static readonly Assembly Domain = typeof(Auth.Domain.AssemblyMarker).Assembly;
    private static readonly Assembly Application = typeof(Auth.Application.AssemblyMarker).Assembly;
    private static readonly Assembly Infrastructure = typeof(Auth.Infrastructure.AssemblyMarker).Assembly;

    [Fact]
    public void Domain_does_not_depend_on_other_layers_or_frameworks()
    {
        var result = Types.InAssembly(Domain).ShouldNot()
            .HaveDependencyOnAny("Auth.Application", "Auth.Infrastructure", "Auth.Api", "Microsoft.AspNetCore", "Microsoft.EntityFrameworkCore")
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(string.Join(", ", result.FailingTypeNames ?? []));
    }

    [Fact]
    public void Application_does_not_depend_on_ef_core_aspnet_or_outer_layers()
    {
        var result = Types.InAssembly(Application).ShouldNot()
            .HaveDependencyOnAny("Auth.Infrastructure", "Auth.Api", "Microsoft.AspNetCore", "Microsoft.EntityFrameworkCore")
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(string.Join(", ", result.FailingTypeNames ?? []));
    }

    [Fact]
    public void Infrastructure_does_not_depend_on_api()
    {
        var result = Types.InAssembly(Infrastructure).ShouldNot()
            .HaveDependencyOn("Auth.Api")
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(string.Join(", ", result.FailingTypeNames ?? []));
    }
}
