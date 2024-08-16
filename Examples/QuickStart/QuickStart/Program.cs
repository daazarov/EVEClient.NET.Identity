using EVEClient.NET.Identity;
using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication;

namespace QuickStart
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllersWithViews();

            var esiSection = builder.Configuration.GetRequiredSection("EVEClient.NET.Identity");

            builder.Services.AddEVEOnlineEsiClient(config => config.UserAgent = "github.com/daazarov/EVEClient.NET.Identity Quick Start")
                            .AddAuthentication(option =>
                            {
                                option.ClientId = esiSection.GetValue<string>("ClientId")!;
                                option.ClientSecret = esiSection.GetValue<string>("ClientSecret")!;
                                option.CallbackPath = esiSection.GetValue<string>("CallbackPath")!;
                                option.Scopes.AddRange(esiSection.GetSection("Scopes").Get<string[]>()!);

                                option.OAuthEvents.OnFailedRenewAccessToken = OnFailedRenewAccessTokenListener;
                            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            // You don't need to call app.UseAuthentication() directly. The UseEsiAuthentication() method already contains its call by default.
            app.UseEsiAuthentication();
            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }

        private static async Task OnFailedRenewAccessTokenListener(EveRenewAccessTokenFailureContext context)
        {
            // forced redirect to the login page (Account/Login) to get a new set of tokens
            await context.HttpContext.ChallengeAsync(await context.HttpContext.GetEveCookieAuthenticationSchemeName());
            await context.HttpContext.Response.StartAsync();
        }
    }
}
