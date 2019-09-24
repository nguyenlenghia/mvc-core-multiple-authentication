# mvc-core-multiple-authentication
multiple authentication guide

#### UPDATE1
```c#
// add policy.
var listAcceptSchema = new[] {
    IdentityServer4.AccessTokenValidation.IdentityServerAuthenticationDefaults.AuthenticationScheme, // a identityserver4 authentication handle
    AppAccessAuthOptions.AuthenticationScheme // a custom authentication handle
};
services.AddMvc(options =>
{
    var policy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder(listAcceptSchema)
    .RequireAuthenticatedUser()
    .Build();
    options.Filters.Add(new Microsoft.AspNetCore.Mvc.Authorization.AuthorizeFilter(policy));
}).SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
```

#### UPDATE 2
As mentioned in comments, you can enable both Identity and JWT auth by join them together. 
```c#
[Authorize(AuthenticationSchemes = IdentityServer4.AccessTokenValidation.IdentityServerAuthenticationDefaults.AuthenticationScheme + "," + AppAccessAuthOptions.AuthenticationScheme)]
```


#### Example
```c#
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Reflection;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using ThmApi.ViberService.Domain.Models;
using ThmApi.ViberService.Domain.Services;

namespace ThmApi.ViberService
{
    /// <summary>
    /// The class to config the application authentication
    /// </summary>
    internal static class ApiAuthenticationConfiguration
    {
        /// <summary>
        /// Use this method to add services to the container.
        /// </summary>
        public static void Configure(IServiceCollection services, IConfiguration configuration = null)
        {
            var scheme = IdentityServerAuthenticationDefaults.AuthenticationScheme;

            // configure jwt authentication
            services.AddAuthentication(scheme)
            .AddIdentityServerAuthentication(scheme, options =>
            {
                options.Authority = "https://localhost:44333";
                options.RequireHttpsMetadata = false;

                options.ApiName = $"api.{Assembly.GetExecutingAssembly().GetName().Name}";
                //options.ApiSecret = "secret";

                // load options from config
                configuration.GetSection("ApiAuthentication").Bind(options);
                // validate options
                options.Validate();
            })
            .AddAppAccessAuthentication();

            services.AddCors();
        }

        /// <summary>
        /// Use this method to configure the HTTP request pipeline.
        /// </summary>
        public static void Configure(IApplicationBuilder app, IConfiguration configuration = null)
        {
            // Both UseAuthentication and UseCors need to come before UseMvc if not, you need set DefaultPolicy
            app.UseAuthentication();

            // global cors policy
            app.UseCors(x => x
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader());
        }
    }

    /// <summary>
    /// Class AppAccessAuthenticationBuilderExtensions.
    /// </summary>
    static class AppAccessAuthenticationBuilderExtensions
    {
        /// <summary>
        /// Adds the API key authentication.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns>AuthenticationBuilder.</returns>
        public static AuthenticationBuilder AddAppAccessAuthentication(this AuthenticationBuilder builder, Action<AppAccessAuthOptions> configureOptions = null)
        {
            // Add custom authentication scheme with custom options and custom handler
            return builder.AddScheme<AppAccessAuthOptions, AppAccessAuthenticationHandler>(AppAccessAuthOptions.AuthenticationScheme, configureOptions);
        }
    }

    /// <summary>
    /// Class AppAccessAuthOptions.
    /// </summary>
    class AppAccessAuthOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// The authentication scheme
        /// </summary>
        public const string AuthenticationScheme = "AppAccess";
        /// <summary>
        /// The authentication type
        /// </summary>
        public const string AuthenticationType = "AppAccess";
    }

    /// <summary>
    /// Class AppAccessAuthenticationHandler.
    /// </summary>
    class AppAccessAuthenticationHandler : AuthenticationHandler<AppAccessAuthOptions>
    {
        private readonly IAppAccessService _userService;

        /// <summary>
        /// Initializes a new instance of the <see cref="AppAccessAuthenticationHandler"/> class.
        /// </summary>
        public AppAccessAuthenticationHandler(
            IOptionsMonitor<AppAccessAuthOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IAppAccessService userService)
            : base(options, logger, encoder, clock)
        {
            _userService = userService;
        }

        /// <summary>
        /// handle authenticate as an asynchronous operation.
        /// </summary>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("AppId") || !Request.Headers.ContainsKey("AppKey"))
                return AuthenticateResult.Fail("Missing Authorization Header AppId or AppKey");

            AppAccess user = null;
            try
            {
                //var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                //var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
                //var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':');
                //var username = credentials[0];
                //var password = credentials[1];

                var username = Request.Headers["AppId"];
                var password = Request.Headers["AppKey"];

                var resuser = _userService.Validate(username, password);
                if (resuser.Failure)
                    return AuthenticateResult.Fail("Invalid Authorization. " + resuser.Message);

                user = resuser.Result;
            }
            catch
            {
                return AuthenticateResult.Fail("Invalid Authorization Header");
            }

            if (user == null)
                return AuthenticateResult.Fail("Invalid Username or Password");

            var claims = new[] {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Name),
                new Claim("client_id", user.Id),
                // other claims...
            };
            var identity = new ClaimsIdentity(claims, AppAccessAuthOptions.AuthenticationType);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, AppAccessAuthOptions.AuthenticationScheme);

            return AuthenticateResult.Success(ticket);
        }
    }
}
```

##### Documents
+ https://stackoverflow.com/questions/45778679/dotnet-core-2-0-authentication-multiple-schemas-identity-cookies-and-jwt
+ https://stackoverflow.com/questions/54260837/multiple-authentication-methods-in-asp-net-core-2-2
+ https://jasonwatmore.com/post/2018/09/08/aspnet-core-21-basic-authentication-tutorial-with-example-api
+ https://medium.com/agilix/asp-net-core-supporting-multiple-authorization-6502eb79f934
+ https://bitoftech.net/2014/06/01/token-based-authentication-asp-net-web-api-2-owin-asp-net-identity/
