using System.Collections.Generic;
using System.Web.Http;

namespace OtherSecureApi.Controllers
{
    [Authorize]
    public class IdentityController : ApiController
    {
        // GET api/values
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }
    }
}
