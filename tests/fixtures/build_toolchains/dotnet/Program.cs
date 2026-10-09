using Newtonsoft.Json.Linq;

var parsed = JObject.Parse("{\"name\":\"appsec fixture\"}");
Console.WriteLine(parsed["name"]);
