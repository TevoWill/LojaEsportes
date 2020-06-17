using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using LojaEsportes.Models.ViewModels;

namespace LojaEsportes.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private UserManager<IdentityUser> userManager;
        private SignInManager<IdentityUser> signInManager;

        public AccountController(UserManager<IdentityUser> userMgr,
            SignInManager<IdentityUser> signInMgr)
        {
            userManager = userMgr;
            signInManager = signInMgr;
        }

        [AllowAnonymous]
        public ViewResult Login(string returnUrl) {
            return View(
                new LoginModel { ReturnUrl = returnUrl }
            );
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel loginModel) {
            if (ModelState.IsValid) {
                // Efetuando a busca do usuário pelo nome/login
                IdentityUser user =
                    await userManager.FindByNameAsync(loginModel.Name);
                if (user != null) {
                    // Garante que o usuário não logará mais de uma vez
                    await signInManager.SignOutAsync();
                    // Checagem de senha
                    if ( (await signInManager.PasswordSignInAsync(user,
                            loginModel.Password, false, false)).Succeeded ) {
                        return Redirect(loginModel?.ReturnUrl ?? "/Admin/Index");
                    }
                }                
            }
            ModelState.AddModelError("", "Usuário ou Senha inválidos");
            return View(loginModel);
        }

        public async Task<RedirectResult> Logout(string returnUrl = "/") {
            await signInManager.SignOutAsync();
            return Redirect(returnUrl);
        }
    }
}
