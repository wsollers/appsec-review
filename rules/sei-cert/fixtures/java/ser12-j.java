// SEI CERT SER12-J focused fixture.
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;

class Loader {
    Object load(String name) throws IOException, ClassNotFoundException {
        try (ObjectInputStream input = new ObjectInputStream(new FileInputStream(name))) {
            // cert: positive appsec-review.sei-cert.java.ser12-j.unfiltered-object-deserialization
            return input.readObject();
        }
    }

    Object loadUnshared(InputStream stream) throws IOException, ClassNotFoundException {
        ObjectInputStream input = new ObjectInputStream(stream);
        // cert: variant appsec-review.sei-cert.java.ser12-j.unfiltered-object-deserialization
        return input.readUnshared();
    }

    Object loadFiltered(InputStream stream) throws IOException, ClassNotFoundException {
        ObjectInputStream input = new ObjectInputStream(stream);
        input.setObjectInputFilter(ObjectInputFilter.Config.createFilter("app.Settings;!*"));
        // cert: safe-alternative appsec-review.sei-cert.java.ser12-j.unfiltered-object-deserialization
        return input.readObject();
    }

    Object loadLookAhead(InputStream stream) throws IOException, ClassNotFoundException {
        ObjectInputStream input = new ObjectInputStream(stream) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass description)
                    throws IOException, ClassNotFoundException {
                if (!description.getName().equals("app.Settings")) {
                    throw new java.io.InvalidClassException(description.getName());
                }
                return super.resolveClass(description);
            }
        };
        // cert: negative appsec-review.sei-cert.java.ser12-j.unfiltered-object-deserialization
        return input.readObject();
    }

    int readHeader(InputStream stream) throws IOException {
        ObjectInputStream input = new ObjectInputStream(stream);
        // cert: near-miss appsec-review.sei-cert.java.ser12-j.unfiltered-object-deserialization
        return input.readInt();
    }

    /** Reads the bundled defaults file shipped inside the signed application archive. */
    Object loadBundledDefaults() throws IOException, ClassNotFoundException {
        try (ObjectInputStream input = new ObjectInputStream(Loader.class.getResourceAsStream("/defaults.bin"))) {
            // cert: unmodeled-exception:SER12-EX0 appsec-review.sei-cert.java.ser12-j.unfiltered-object-deserialization
            return input.readObject();
        }
    }
}
