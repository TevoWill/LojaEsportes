#pragma checksum "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "4bb172708dce97dfc93142be4c2a51714783c377"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Order_List), @"mvc.1.0.view", @"/Views/Order/List.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Order/List.cshtml", typeof(AspNetCore.Views_Order_List))]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#line 1 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\_ViewImports.cshtml"
using LojaEsportes.Models;

#line default
#line hidden
#line 2 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\_ViewImports.cshtml"
using LojaEsportes.Models.ViewModels;

#line default
#line hidden
#line 3 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\_ViewImports.cshtml"
using LojaEsportes.Infrastructure;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"4bb172708dce97dfc93142be4c2a51714783c377", @"/Views/Order/List.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"27cb678309882ac3c39e94d9de0c05914b889798", @"/Views/_ViewImports.cshtml")]
    public class Views_Order_List : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<IEnumerable<Order>>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "MarkShipped", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("method", "post", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(27, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 3 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
   
    ViewBag.Title = "Lista de Pedidos";
    Layout = "_AdminLayout";

#line default
#line hidden
            BeginContext(108, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 8 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
 if (Model.Count() > 0)
{

#line default
#line hidden
            BeginContext(138, 519, true);
            WriteLiteral(@"    <table class=""table table-bordered table-striped"">
        <!-- Linha de cabeçalho da lista de pedidos
             Não repete, exibe apenas uma vez -->
        <tr>
            <th>Nome</th>
            <th>CEP</th>
            <th>Produto</th>
            <th>Quantidade</th>
        </tr>
        <!-- Laço de repetição para os pedidos
             Cada pedido pode haver N produtos
             portanto para não repetir informações
             desnecessárias exibimos o pedido apenas uma vez -->
");
            EndContext();
#line 23 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
         foreach (Order o in Model)
        {

#line default
#line hidden
            BeginContext(705, 38, true);
            WriteLiteral("            <tr>\r\n                <td>");
            EndContext();
            BeginContext(744, 6, false);
#line 26 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
               Write(o.Name);

#line default
#line hidden
            EndContext();
            BeginContext(750, 27, true);
            WriteLiteral("</td>\r\n                <td>");
            EndContext();
            BeginContext(778, 5, false);
#line 27 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
               Write(o.Zip);

#line default
#line hidden
            EndContext();
            BeginContext(783, 188, true);
            WriteLiteral("</td>\r\n                <td>Produto</td>\r\n                <td>Quantidade</td>\r\n                <td>\r\n                    <!-- Botão para marcar pedido como enviado -->\r\n                    ");
            EndContext();
            BeginContext(971, 572, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("form", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "4b359aa9b62247a9bfc98e09593f6c93", async() => {
                BeginContext(1016, 261, true);
                WriteLiteral(@"
                        <!-- Informação oculta do ID do pedido
                             para atender o parâmetro solicitado
                             do método MarkShipped do Controller -->
                        <input type=""hidden"" name=""orderId""");
                EndContext();
                BeginWriteAttribute("value", "\r\n                               value=\"", 1277, "\"", 1327, 1);
#line 37 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
WriteAttributeValue("", 1317, o.OrderID, 1317, 10, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(1328, 208, true);
                WriteLiteral(" />\r\n                        <button type=\"submit\"\r\n                                class=\"btn btn-sm btn-danger\">\r\n                            Enviado\r\n                        </button>\r\n                    ");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Action = (string)__tagHelperAttribute_0.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_0);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Method = (string)__tagHelperAttribute_1.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_1);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(1543, 154, true);
            WriteLiteral("\r\n                </td>\r\n            </tr>\r\n            <!-- Exibição dos produtos do pedido \r\n                 relação de N-Pedidos para N-Produtos -->\r\n");
            EndContext();
#line 47 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
             foreach (CartLine line in o.Lines)
            {

#line default
#line hidden
            BeginContext(1761, 89, true);
            WriteLiteral("                <tr>\r\n                    <td colspan=\"2\"></td>\r\n                    <td>");
            EndContext();
            BeginContext(1851, 17, false);
#line 51 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
                   Write(line.Product.Name);

#line default
#line hidden
            EndContext();
            BeginContext(1868, 31, true);
            WriteLiteral("</td>\r\n                    <td>");
            EndContext();
            BeginContext(1900, 13, false);
#line 52 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
                   Write(line.Quantity);

#line default
#line hidden
            EndContext();
            BeginContext(1913, 30, true);
            WriteLiteral("</td>\r\n                </tr>\r\n");
            EndContext();
#line 54 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
            }

#line default
#line hidden
#line 54 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
             
        }

#line default
#line hidden
            BeginContext(1969, 14, true);
            WriteLiteral("    </table>\r\n");
            EndContext();
#line 57 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
}
else
{

#line default
#line hidden
            BeginContext(1995, 85, true);
            WriteLiteral("    <div class=\"text-center\">\r\n        Não há pedidos a serem enviados.\r\n    </div>\r\n");
            EndContext();
#line 63 "C:\Users\tevo\source\repos\LojaEsportes\LojaEsportes\Views\Order\List.cshtml"
}

#line default
#line hidden
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<IEnumerable<Order>> Html { get; private set; }
    }
}
#pragma warning restore 1591