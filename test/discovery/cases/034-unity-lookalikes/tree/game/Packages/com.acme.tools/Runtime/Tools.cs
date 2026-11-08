namespace Acme.Tools
{
    public static class Clamp
    {
        public static int To(int value, int max) => value > max ? max : value;
    }
}
