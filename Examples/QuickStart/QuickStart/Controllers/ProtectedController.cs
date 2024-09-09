using EVEClient.NET;
using EVEClient.NET.DataContract;
using EVEClient.NET.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace QuickStart.Controllers
{
    [Authorize]
    public class ProtectedController : Controller
    {
        private readonly IEsiLogicAccessor _logicAccessor;
        private readonly IEveUserAccessor<EveOnlineUser> _userAccessor;
        
        public ProtectedController(IEsiLogicAccessor logicAccessor, IEveUserAccessor<EveOnlineUser> userAccessor)
        { 
            _logicAccessor = logicAccessor;
            _userAccessor = userAccessor;
        }

        public async Task<IActionResult> Index()
        {
            var mails = await _logicAccessor.MailLogic.MailHeaders(_userAccessor.Current!.CharacterId);
            if (mails.Success)
            { 
                return View(mails.Data);
            }

            return View(new List<Header>());
        }
    }
}
