﻿using LojaEsportes.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace LojaEsportes.Controllers
{    
    public class OrderController : Controller
    {
        private IOrderRepository repository;
        private Cart cart;

        public OrderController(
            IOrderRepository repoService,
            Cart cartService)
        {
            repository = repoService;
            cart = cartService;
        }

        [Authorize]
        public ViewResult List() =>
            View(repository.Orders.Where(o => !o.Shipped));

        [HttpPost]
        [Authorize]
        public IActionResult MarkShipped( int orderID ) {
            // Busca o pedido a ser marcado como enviado
            Order order = repository.Orders
                .FirstOrDefault(o => o.OrderID == orderID);
            if (order != null) {
                // Atualiza propriedade do pedido para enviado
                order.Shipped = true;
                // Salva no EF
                repository.SaveOrder(order);
            }
            return RedirectToAction(nameof(List));
        }

        public ViewResult Checkout() => 
            View( new Order() );

        [HttpPost]
        public IActionResult Checkout( Order order )
        {
            if (cart.Lines.Count() == 0) {
                ModelState.AddModelError("", 
                    "Erro! Carrinho eestá vazio!");
            }

            if (ModelState.IsValid)
            {
                order.Lines = cart.Lines.ToArray();
                repository.SaveOrder(order);
                return RedirectToAction(nameof(Completed));
            }
            else
            {
                return View(order);
            }
        }

        public ViewResult Completed() {
            cart.Clear();
            return View();
        }
    }
}
