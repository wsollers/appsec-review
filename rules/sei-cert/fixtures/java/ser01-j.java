// SEI CERT SER01-J focused fixture.
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.io.Serializable;

class PublicHooks implements Serializable {
    private static final long serialVersionUID = 1L;

    // cert: positive appsec-review.sei-cert.java.ser01-j.serialization-hook-signature
    public void writeObject(ObjectOutputStream stream) throws IOException {
        stream.defaultWriteObject();
    }

    // cert: variant appsec-review.sei-cert.java.ser01-j.serialization-hook-signature
    private static void readObject(final ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();
    }

    // cert: variant appsec-review.sei-cert.java.ser01-j.serialization-hook-signature
    protected void readObjectNoData() throws ObjectStreamException {
    }

    // cert: positive appsec-review.sei-cert.java.ser01-j.static-replacement-hook
    protected static Object readResolve() {
        return null;
    }

    // cert: variant appsec-review.sei-cert.java.ser01-j.static-replacement-hook
    public static final Object writeReplace() {
        return null;
    }
}

class CorrectHooks implements Serializable {
    private static final long serialVersionUID = 1L;

    // cert: safe-alternative appsec-review.sei-cert.java.ser01-j.serialization-hook-signature
    private void writeObject(final ObjectOutputStream stream) throws IOException {
        stream.defaultWriteObject();
    }

    // cert: negative appsec-review.sei-cert.java.ser01-j.serialization-hook-signature
    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        stream.defaultReadObject();
    }

    // cert: safe-alternative appsec-review.sei-cert.java.ser01-j.static-replacement-hook
    protected Object writeReplace() {
        return this;
    }
}

class Unrelated {
    // cert: near-miss appsec-review.sei-cert.java.ser01-j.serialization-hook-signature
    public void writeObject(String destination) {
    }

    // cert: near-miss appsec-review.sei-cert.java.ser01-j.static-replacement-hook
    static Object readResolve(String key) {
        return key;
    }
}
