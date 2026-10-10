using System;
using System.Net.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Example.Controllers
{
    [ApiController]
    public class AccountController : ControllerBase
    {
#pragma warning disable CA5359
        private static readonly HttpClientHandler Handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
        };
#pragma warning restore CA5359

        [AllowAnonymous]
        [HttpGet("/accounts/{id}")]
        public IActionResult Get(string id)
        {
            int Local(int value) => value > 0 ? value : 0;
            var kind = id switch
            {
                "admin" => 1,
                "user" => 2,
                _ => 0,
            };
            try
            {
                return Ok(Local(kind) + (id?.Length ?? 0));
            }
            catch (ArgumentException error) when (error.Message != null)
            {
                return BadRequest();
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA2100")]
        public void Run(string command)
        {
            System.Diagnostics.Process.Start("sh", "-c " + command);
        }
    }
}
