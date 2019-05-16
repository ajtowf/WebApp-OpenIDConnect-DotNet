using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;

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
            var identity = await CallApiOnBehalfOfUser();
            return Ok(identity);
        }

        [HttpGet]
        [Route("api/SecureApplicationCallEndpoint")]
        public IHttpActionResult SecureApplicationCallEndpoint()
        {
            var currentContext = HttpContext.Current.GetOwinContext();
            return Ok(currentContext.Authentication.User.Claims.Select(x => new { x.Type, x.Value }));
        }

        public static async Task<object> CallApiOnBehalfOfUser()
        {
            if (!ClaimsPrincipal.Current.FindAll("https://schemas.microsoft.com/identity/claims/scope").Any(x => x.Value.Contains("user_impersonation")))
            {
                throw new HttpResponseException(new HttpResponseMessage { StatusCode = HttpStatusCode.Unauthorized, ReasonPhrase = "The Scope claim does not contain 'user_impersonation' or scope claim not found" });
            }

            var authContext = new AuthenticationContext(Authority, false);

            // ClientId needs to be audience/target resource, can't be guid?!
            // See https://docs.microsoft.com/sv-se/windows-server/identity/ad-fs/development/ad-fs-on-behalf-of-authentication-in-windows-server
            // It is very important that the ida:Audience and ida:ClientID match each other
            var credential = new ClientCredential(ClientId, ClientSecret);

            var bootstrapContext = new System.IdentityModel.Tokens.BootstrapContext(ClaimsPrincipal.Current.Identities.First().BootstrapContext.ToString());
            var userName = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn) != null ? ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn).Value : ClaimsPrincipal.Current.FindFirst(ClaimTypes.Email).Value;
            var userAccessToken = bootstrapContext.Token;
            var userAssertion = new UserAssertion(userAccessToken, "urn:ietf:params:oauth:grant-type:jwt-bearer", userName);

            var tokenResult = await authContext.AcquireTokenAsync(Resource, credential, userAssertion);

            var client = new HttpClient();

            var requestUri = $"{Resource}api/identity";
            var request = new HttpRequestMessage(HttpMethod.Get, requestUri);

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResult.AccessToken);
            var response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var claimsIdentity = JsonConvert.DeserializeObject<object>(content);
                return claimsIdentity;
            }

            return "Unsuccessful OBO operation : " + response.ReasonPhrase;
        }
    }
}
