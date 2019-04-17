//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

// The following using statements were added for this sample.

using System;
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Configuration;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Protocols;

namespace WebApp_OpenIDConnect_DotNet
{
    public partial class Startup
    {
        private static readonly string ClientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static readonly string ClientSecret = ConfigurationManager.AppSettings["ida:ClientSecret"];
        private static readonly string Authority = ConfigurationManager.AppSettings["ida:Authority"];
        private static readonly string PostLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];
        private static readonly string Resource = ConfigurationManager.AppSettings["ida:Resource"];

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    Authority = Authority,
                    MetadataAddress = $"{Authority}/.well-known/openid-configuration",

                    ClientId = ClientId,
                    ClientSecret = ClientSecret,

                    Resource = Resource,
                    ResponseType = OpenIdConnectResponseTypes.CodeIdToken,
                    Scope = "openid profile user_impersonation",

                    RedirectUri = PostLogoutRedirectUri,
                    PostLogoutRedirectUri = PostLogoutRedirectUri,

                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthorizationCodeReceived = async context => 
                        {
                            var authContext = new AuthenticationContext(Authority, false);

                            var authResult = await authContext.AcquireTokenByAuthorizationCodeAsync(
                                context.Code,                                 
                                new Uri(context.RedirectUri), 
                                new ClientCredential(context.Options.ClientId, context.Options.ClientSecret),
                                Resource);
                            
                            context.AuthenticationTicket.Identity.AddClaim(new Claim("id_token", authResult.IdToken));
                            context.AuthenticationTicket.Identity.AddClaim(new Claim("access_token", authResult.AccessToken));
                        },
                       
                        AuthenticationFailed = context => 
                        {
                            context.HandleResponse();
                            context.Response.Redirect("/Error?message=" + context.Exception.Message);
                            return Task.FromResult(0);
                        },

                        RedirectToIdentityProvider = n =>
                        {
                            if (n.ProtocolMessage.RequestType == Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectRequestType.Logout)
                            {
                                var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");
                                if (idTokenHint != null)
                                {
                                    n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                                }
                            }

                            return Task.FromResult(0);
                        }
                    }
                });
        }
    }
}