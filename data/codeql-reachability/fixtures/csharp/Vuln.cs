namespace Example.Vuln
{
    /// <summary>Stands in for a dependency with an advisory on Parser.Parse (smoke fixture).</summary>
    public static class Parser
    {
        public static string Parse(string s) => s;
    }
}
