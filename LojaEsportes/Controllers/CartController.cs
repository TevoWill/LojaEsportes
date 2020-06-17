﻿using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using LojaEsportes.Infrastructure;
using LojaEsportes.Models;
using LojaEsportes.Models.ViewModels;

namespace LojaEsportes.Controllers
{
    public class CartController : Controller
    {
        private IProductRepository repository;
        private Cart cart;

        public CartController(IProductRepository repo, Cart cartService) {
            repository = repo;
            cart = cartService;
        }

        public ViewResult Index( string returnUrl ) {
            return View(
                new CartIndexViewModel {
                    Cart = cart,
                    ReturnUrl = returnUrl
                }
            );
        }

        public RedirectToActionResult AddToCart(
            int productId, string returnUrl) {

            Product product = repository.Products
                .FirstOrDefault(p => p.ProductID == productId);

            if (product != null) {
                //Cart cart = GetCart();
                cart.AddItem(product, 1);
                SaveCart(cart);
            }

            return RedirectToAction("Index", new { returnUrl });
        }

        public RedirectToActionResult RemoveFromCart(
            int productId, string returnUrl) {

            Product product = repository.Products.FirstOrDefault(
                p => p.ProductID == productId);

            if (product != null) {
                //Cart cart = GetCart();
                cart.RemoveLine(product);
                SaveCart(cart);
            }

            return RedirectToAction("Index", new { returnUrl });
        }

        private Cart GetCart() {
            Cart cart = HttpContext.Session.GetJson<Cart>("Cart") ?? new Cart();
            return cart;
        }

        private void SaveCart(Cart cart) {
            HttpContext.Session.SetJson("Cart", cart);
        }

    }
}
