// SEI CERT IDS07-J focused fixture.
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class Launcher {
    public static void main(String[] args) throws IOException {
        String value = args.length > 0 ? args[0] : "sample";
        String[] command = {"sh", "-c", "printf '%s' " + value};
        // cert: positive appsec-review.sei-cert.java.ids07-j.untrusted-data-to-process-execution
        Runtime.getRuntime().exec(command);
    }

    void listDirectory() throws IOException {
        String dir = System.getProperty("dir");
        // cert: variant appsec-review.sei-cert.java.ids07-j.untrusted-data-to-process-execution
        Runtime.getRuntime().exec("cmd.exe /C dir " + dir);
    }

    void archive(HttpServletRequest request) throws IOException {
        String name = request.getParameter("name");
        // cert: variant appsec-review.sei-cert.java.ids07-j.untrusted-data-to-process-execution
        new ProcessBuilder("tar", "-czf", name).start();
    }

    void fixedCommand() throws IOException {
        // cert: negative appsec-review.sei-cert.java.ids07-j.untrusted-data-to-process-execution
        new ProcessBuilder("ls", "-l").start();
    }

    void numericArgument(HttpServletRequest request) throws IOException {
        int lines = Integer.parseInt(request.getParameter("lines"));
        // cert: safe-alternative appsec-review.sei-cert.java.ids07-j.untrusted-data-to-process-execution
        new ProcessBuilder("tail", "-n", Integer.toString(lines), "/var/log/app.log").start();
    }

    void logOnly(HttpServletRequest request) {
        String name = request.getParameter("name");
        // cert: near-miss appsec-review.sei-cert.java.ids07-j.untrusted-data-to-process-execution
        System.out.println("archive " + name);
    }

    private static void run(String command) throws IOException {
        Runtime.getRuntime().exec(command);
    }

    void interprocedural() throws IOException {
        String dir = System.getenv("TARGET_DIR");
        // cert: known-false-negative appsec-review.sei-cert.java.ids07-j.untrusted-data-to-process-execution
        run("ls " + dir);
    }
}
