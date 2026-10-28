package app;

public class Cli {
    public static void main(String[] args) throws Exception {
        String home = System.getenv("APP_HOME");
        new Server(null, new MemoryStore()).runCommand(args[0]);
        new Server(null, new FileStore()).fetch(home);
    }
}
