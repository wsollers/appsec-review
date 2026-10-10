// SEI CERT ERR07-J focused fixture.
import java.io.IOException;

class Accounts {
    void withdraw(long amount) {
        if (amount < 0) {
            // cert: positive appsec-review.sei-cert.java.err07-j.throw-generic-exception
            throw new RuntimeException("negative amount");
        }
    }

    // cert: variant appsec-review.sei-cert.java.err07-j.declares-generic-exception
    void close() throws Exception {
        // cert: variant appsec-review.sei-cert.java.err07-j.throw-generic-exception
        throw new java.lang.Exception("closing");
    }

    // cert: positive appsec-review.sei-cert.java.err07-j.declares-generic-exception
    void load() throws Exception {
        throw new IOException("unavailable");
    }

    // cert: variant appsec-review.sei-cert.java.err07-j.declares-generic-exception
    void refresh() throws IOException, Throwable {
        throw new IOException("unavailable");
    }

    void validate(long amount) {
        if (amount < 0) {
            // cert: safe-alternative appsec-review.sei-cert.java.err07-j.throw-generic-exception
            throw new IllegalArgumentException("negative amount");
        }
    }

    void reject(long amount) {
        // cert: near-miss appsec-review.sei-cert.java.err07-j.throw-generic-exception
        throw new ApplicationRuntimeException("rejected " + amount);
    }

    // cert: negative appsec-review.sei-cert.java.err07-j.declares-generic-exception
    long balance() {
        return 0L;
    }

    // cert: near-miss appsec-review.sei-cert.java.err07-j.declares-generic-exception
    void read() throws IOException {
        throw new IOException("unavailable");
    }

    public static void main(String[] args) throws Exception {
        // cert: negative appsec-review.sei-cert.java.err07-j.throw-generic-exception
        new Accounts().validate(1);
    }
}

class ApplicationRuntimeException extends RuntimeException {
    ApplicationRuntimeException(String message) {
        super(message);
    }
}

final class SanitizingGateway {
    Object call(java.util.concurrent.Callable<Object> task) {
        try {
            return task.call();
        } catch (Exception internal) {
            // cert: unmodeled-exception:ERR07-J-EX0 appsec-review.sei-cert.java.err07-j.throw-generic-exception
            throw new RuntimeException("request failed");
        }
    }
}
