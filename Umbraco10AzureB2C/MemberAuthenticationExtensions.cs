using System.Security.Claims;

namespace Umbraco10AzureB2C
{
    public static class MemberAuthenticationExtensions
    {
        public static IUmbracoBuilder ConfigureAuthenticationMembers(this IUmbracoBuilder builder)
        {
            builder.Services.ConfigureOptions<AzureB2CMembersExternalLoginProviderOptions>();



            builder.AddMemberExternalLogins(logins =>
            {
                //const string schema = MicrosoftAccountDefaults.AuthenticationScheme;

                logins.AddMemberLogin(
                    membersAuthenticationBuilder =>
                    {
                        membersAuthenticationBuilder.AddOpenIdConnect(
                    membersAuthenticationBuilder.SchemeForMembers(AzureB2CMembersExternalLoginProviderOptions.SchemeName),
                    options =>
                    {
                        options.SaveTokens = true;
                        //Obtained from the AZURE AD B2C WEB APP
                        options.ClientId = "";
                        //Obtained from the AZURE AD B2C WEB APP
                        options.ClientSecret = "";
                        //Callbackpath - Important! The CallbackPath represents the URL to which the browser should be redirected to and the default value is /signin-oidc.
                        options.CallbackPath = "/umbraco-b2c-signin";

                        //Obtained from user flows in your Azure B2C tenant
                        options.MetadataAddress =
                            "https://muslimb2ctest.b2clogin.com/muslimb2ctest.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=B2C_1_Muslimsignupsignin";


                        options.Events.OnTokenValidated = async context =>
                        {
                            ClaimsPrincipal? principal = context.Principal;
                            if (principal is null)
                            {
                                throw new InvalidOperationException("No claims found.. :(");
                                return;
                            }

                            var claims = principal.Claims.ToList();

                            Claim? email = claims.SingleOrDefault(x => x.Type == "emails");
                            if (email is not null)
                            {
                                claims.Add(new Claim(ClaimTypes.Email, email.Value));
                            }

                            Claim? name = claims.SingleOrDefault(x => x.Type == "name");
                            if (name is not null)
                            {
                                claims.Add(new Claim(ClaimTypes.Name, name.Value));
                            }

                            var authenticationType = principal.Identity?.AuthenticationType;
                            context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType));
                        };
                    });
                    });
            });

            return builder;
        }
    }
}

