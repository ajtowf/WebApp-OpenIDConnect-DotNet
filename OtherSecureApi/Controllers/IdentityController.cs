using System.Linq;
using System.Security.Claims;
using System.Web.Http;

namespace OtherSecureApi.Controllers
{
    [Authorize]
    public class IdentityController : ApiController
    {
        [HttpGet]
        public IHttpActionResult Get()
        {
            var identity = ((ClaimsIdentity)User.Identity).Claims.Select(x => new { x.Type, x.Value });
            return Ok(identity);
        }
    }
}
