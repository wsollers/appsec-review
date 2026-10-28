using System;
using System.Data.Common;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Xml.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace Synthetic
{
    public interface IStore
    {
        string Load(string key);
    }

    public class FileStore : IStore
    {
        public string Load(string key)
        {
            File.Delete(key);
            return key;
        }
    }

    public class MemoryStore : IStore
    {
        public string Load(string key)
        {
            return key;
        }
    }

    public static class Helpers
    {
        public static string Wrap(string value)
        {
            return "'" + value + "'";
        }

        public static string Apply(Func<string, string> transform, string value)
        {
            return transform(value);
        }
    }

    [ApiController]
    [Route("items")]
    public class ItemsController : ControllerBase
    {
        private readonly DbConnection connection;
        private readonly HttpClient client;
        private readonly IStore store;

        public ItemsController(DbConnection connection, HttpClient client, IStore store)
        {
            this.connection = connection;
            this.client = client;
            this.store = store;
        }

        [HttpGet("query")]
        public IActionResult Query(string name)
        {
            DbCommand command = connection.CreateCommand();
            command.CommandText = "SELECT id FROM items WHERE name = " + Helpers.Wrap(name);
            return Ok(command.ExecuteScalar());
        }

        [HttpPost("run")]
        public IActionResult Run(string tool)
        {
            if (tool.Length < 16)
            {
                Process.Start(tool);
            }
            Process.Start(tool + " --verbose");
            return Ok();
        }

        [HttpGet("fetch")]
        public IActionResult Fetch(string url)
        {
            return Ok(client.GetStringAsync(url).Result);
        }

        [HttpGet("read")]
        public IActionResult Read(string name)
        {
            File.Delete(Path.GetFileName(name));
            return Ok(store.Load(name));
        }

        [HttpPost("import")]
        public IActionResult Import(string body, string typeName)
        {
            Type type = Type.GetType(typeName);
            object created = Activator.CreateInstance(type);
            object value = new XmlSerializer(type).Deserialize(new StringReader(body));
            return Ok(new[] { created, value });
        }

        [HttpPost("allocate")]
        public IActionResult Allocate(int count, long length)
        {
            if (count > 0 && count <= 4096)
            {
                byte[] buffer = new byte[count];
                return Ok(buffer.Length);
            }
            byte[] data = new byte[(int)length];
            return Ok(data.Length);
        }
    }

    public static class Program
    {
        public static string Normalize(string value)
        {
            return value.Trim();
        }

        public static void Main(string[] args)
        {
            string home = Environment.GetEnvironmentVariable("APP_HOME");
            File.Delete(Path.Combine(home, args[0]));
            string normalized = Helpers.Apply(Normalize, args[0]);
            dynamic sink = new MemoryStore();
            sink.Flush(normalized);
        }
    }
}
