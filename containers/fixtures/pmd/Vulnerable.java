public final class Vulnerable {
    private Vulnerable() {}

    public static Process run(String command) throws java.io.IOException {
        return Runtime.getRuntime().exec(command);
    }
}
