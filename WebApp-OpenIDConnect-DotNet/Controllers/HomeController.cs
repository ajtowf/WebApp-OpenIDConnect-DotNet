using System.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Mvc;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;

namespace WebApp_OpenIDConnect_DotNet.Controllers
{
    
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public async Task<ActionResult> Secure()
        {
            var secureData = await CallApiOnBehalfOfUser();
            ViewBag.SecureData = secureData;

            return View();
        }

        [AllowAnonymous]
        public async Task<ActionResult> CallAsApplication()
        {
            var authContext = new AuthenticationContext(ConfigurationManager.AppSettings["ida:Authority"], false);

            var result = await authContext.AcquireTokenAsync(
                ConfigurationManager.AppSettings["ida:Resource"],
                new ClientCredential(
                    ConfigurationManager.AppSettings["ida:ClientId"],
                    ConfigurationManager.AppSettings["ida:ClientSecret"]));

            var client = new HttpClient();
            var requestUri = ConfigurationManager.AppSettings["ida:Resource"] + "api/SecureApplicationCallEndpoint";
            var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
            var response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                var formattedResponse = JsonConvert.SerializeObject(JsonConvert.DeserializeObject<object>(content), Formatting.Indented);
                ViewBag.SecureData = formattedResponse;
            }
            else
            {
                ViewBag.SecureData = "Unsuccessful OBO operation : " + response.ReasonPhrase;
            }

            return View();
        }

        public static async Task<string> CallApiOnBehalfOfUser()
        {
            var client = new HttpClient();

            var requestUri = ConfigurationManager.AppSettings["ida:Resource"] + "/api/identity";
            var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ClaimsPrincipal.Current.FindFirst("access_token").Value);
            var response = await client.SendAsync(request);
            
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                var formattedResponse = JsonConvert.SerializeObject(JsonConvert.DeserializeObject<object>(content), Formatting.Indented);
                return formattedResponse;
            }

            return "Unsuccessful OBO operation : " + response.ReasonPhrase;
        }
    }
}