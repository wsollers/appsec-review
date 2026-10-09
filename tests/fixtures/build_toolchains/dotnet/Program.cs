using System.Diagnostics;
using Newtonsoft.Json.Linq;

var parsed = JObject.Parse("{\"name\":\"appsec fixture\"}");
Console.WriteLine(parsed["name"]);

// Intentionally vulnerable test-only flow copied from the pinned query's modeled source/sink.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.MapGet("/run", (HttpRequest request) =>
{
    var command = request.Query["command"].ToString();
    Process.Start("/bin/sh", "-c " + command);
    return Results.Ok();
});
app.Run();
