using System;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace SecureApi.Controllers
{
    [Authorize]
    public class IdentityController : ApiController
    {
        private static readonly string ClientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static readonly string ClientSecret = ConfigurationManager.AppSettings["ida:ClientSecret"];
        private static readonly string Authority = ConfigurationManager.AppSettings["ida:Authority"];
        private static readonly string Resource = ConfigurationManager.AppSettings["ida:Resource"];

        [HttpGet]
        public async Task<IHttpActionResult> Get()
        {
            try
            {
                //var identity = await CallApiOnBehalfOfUser();

                var identity = ((ClaimsIdentity)User.Identity).Claims.Select(x => new { x.Type, x.Value });
                return Ok(identity);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return Unauthorized();
            }
        }

        public static async Task<string> CallApiOnBehalfOfUser()
        {
            var authContext = new AuthenticationContext(Authority, false);
            var credential = new ClientCredential(ClientId, ClientSecret);

            var bootstrapContext = new System.IdentityModel.Tokens.BootstrapContext(ClaimsPrincipal.Current.Identities.First().BootstrapContext.ToString());
            var userName = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn) != null ? ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn).Value : ClaimsPrincipal.Current.FindFirst(ClaimTypes.Email).Value;
            var userAccessToken = bootstrapContext.Token;
            var userAssertion = new UserAssertion(userAccessToken, "urn:ietf:params:oauth:grant-type:jwt-bearer", userName);

            var tokenResult = await authContext.AcquireTokenAsync(Resource, credential, userAssertion);

            var client = new HttpClient();

            var requestUri = ConfigurationManager.AppSettings["ida:Resource"] + "api/identity";
            var request = new HttpRequestMessage(HttpMethod.Get, requestUri);

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResult.AccessToken);
            var response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                return content;
            }

            return "Unsuccessful OBO operation : " + response.ReasonPhrase;
        }
    }
}
