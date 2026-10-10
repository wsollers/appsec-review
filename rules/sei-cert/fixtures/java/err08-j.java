// SEI CERT ERR08-J focused fixture.
class Names {
    static boolean isEmpty(String value) {
        try {
            return value.length() == 0;
        // cert: positive appsec-review.sei-cert.java.err08-j.catch-null-pointer-exception
        } catch (NullPointerException ignored) {
            return true;
        }
    }

    static int parse(String value) {
        try {
            return Integer.parseInt(value.trim());
        // cert: variant appsec-review.sei-cert.java.err08-j.catch-null-pointer-exception
        } catch (NumberFormatException | NullPointerException ignored) {
            return 0;
        }
    }

    static boolean isEmptySafely(String value) {
        // cert: safe-alternative appsec-review.sei-cert.java.err08-j.catch-null-pointer-exception
        return value == null || value.isEmpty();
    }

    static int parseNumber(String value) {
        try {
            return Integer.parseInt(value);
        // cert: near-miss appsec-review.sei-cert.java.err08-j.catch-null-pointer-exception
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    static void runTask(Runnable task) {
        try {
            task.run();
        // cert: exception:ERR08-J-EX1 appsec-review.sei-cert.java.err08-j.catch-null-pointer-exception
        } catch (RuntimeException failure) {
            System.err.println("task failed");
        }
    }
}
