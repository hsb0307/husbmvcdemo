using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using Microsoft.Owin.Security.QQ;

using Owin.Security.Providers.GitHub;

using MVCDemo02.Models;
using System.Collections.Generic;

namespace MVCDemo02
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });            
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Uncomment the following lines to enable logging in with third party login providers
            app.UseMicrosoftAccountAuthentication(
                clientId: "000000004017611E",
                clientSecret: "ZZWAiJv4M09I5a-E0LNFTElaE6Wnlv1I");

            app.UseQQConnectAuthentication(
                appId: "101270486", appSecret: "64389d48959c53bd718118c33ca6c8cb");

            app.UseSinaAuthentication("1312244040", "f62c6ccb6395427926a4e7e8abdcfc04");

            //app.UseGitHubAuthentication(
            //    clientId: "232ffa8d82ab115fb94b",
            //    clientSecret: "ea702bed4d519295e166bb9dda2fcebed441d546");
            var options = new GitHubAuthenticationOptions
            {
                ClientId = "232ffa8d82ab115fb94b",
                ClientSecret = "ea702bed4d519295e166bb9dda2fcebed441d546",
                CallbackPath = new PathString("/oauth-redirect/github"),
                Provider = new GitHubAuthenticationProvider
                {
                    OnAuthenticated = async context =>
                    {
                        // Retrieve the OAuth access token to store for subsequent API calls
                        string accessToken = context.AccessToken;

                        // Retrieve the username
                        string gitHubUserName = context.UserName;

                        // Retrieve the user's email address
                        string gitHubEmailAddress = context.Email;

                        // You can even retrieve the full JSON-serialized user
                        var serializedUser = context.User;

                        context.Identity.AddClaim(new System.Security.Claims.Claim("GitHubAccessToken", context.AccessToken));

                    }
                }
            };
            options.Scope.Add("user");
            options.Scope.Add("repo");
            options.Scope.Add("public_repo");
            options.SignInAsAuthenticationType = DefaultAuthenticationTypes.ExternalCookie;

            app.UseGitHubAuthentication(options);


            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            //app.UseFacebookAuthentication(
            //   appId: "",
            //   appSecret: "");

            //app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            //{
            //    ClientId = "",
            //    ClientSecret = ""
            //});
        }
    }
}