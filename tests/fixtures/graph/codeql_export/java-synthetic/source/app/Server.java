package app;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.sql.Connection;

public class Server {
    private final Connection connection;
    private final Store store;

    public Server(Connection connection, Store store) {
        this.connection = connection;
        this.store = store;
    }

    public void serve(ServerSocket listener) throws Exception {
        Socket socket = listener.accept();
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String line = reader.readLine();
        lookup(line);
        runCommand(line);
        writeChecked(line);
        writeCanonical(line);
        fetch(line);
        store.save(line);
        invokeNamed(line);
        Object payload = new ObjectInputStream(socket.getInputStream()).readObject();
    }

    static String buildQuery(String key) {
        return "SELECT * FROM items WHERE key = '" + key + "'";
    }

    void lookup(String key) throws Exception {
        connection.createStatement().executeQuery(buildQuery(key));
    }

    void runCommand(String command) throws Exception {
        Runtime.getRuntime().exec(command);
    }

    void writeChecked(String name) throws Exception {
        if (name.length() < 64) {
            new FileOutputStream(name).close();
        }
        new FileOutputStream(name + ".log").close();
    }

    void writeCanonical(String name) throws Exception {
        String canonical = new File(name).getCanonicalPath();
        new FileOutputStream(canonical).close();
    }

    void fetch(String address) throws Exception {
        new URL(address).openStream().close();
    }

    void invokeNamed(String name) throws Exception {
        Method method = Class.forName(name).getMethod("run");
        method.invoke(null);
    }
}
