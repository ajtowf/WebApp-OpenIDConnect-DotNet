using System.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.ActiveDirectory;
using Owin;

namespace SecureApi
{
    public class Startup
    {
        private static readonly string Audience = ConfigurationManager.AppSettings["ida:Audience"];
        private static readonly string AdfsMetadataEndpoint = ConfigurationManager.AppSettings["ida:AdfsMetadataEndpoint"];

        public void Configuration(IAppBuilder app)
        {
            app.UseActiveDirectoryFederationServicesBearerAuthentication(
                new ActiveDirectoryFederationServicesBearerAuthenticationOptions
                {
                    MetadataEndpoint = AdfsMetadataEndpoint,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        SaveSigninToken = true,
                        ValidAudience = Audience
                    }
                });
        }
    }
}
