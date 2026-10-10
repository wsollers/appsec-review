package com.example.web;

import com.example.store.UserStore;
import java.io.ObjectInputStream;
import java.util.List;
import javax.annotation.security.PermitAll;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    private final UserStore store = new UserStore();

    @PermitAll
    @PostMapping("/users/import")
    public int importUsers(@RequestBody byte[] body) throws Exception {
        ObjectInputStream input = new ObjectInputStream(new java.io.ByteArrayInputStream(body));
        Object value = input.readObject();
        return value == null ? 0 : 1;
    }

    @SuppressWarnings("unchecked")
    public int score(List<Integer> values, boolean strict) {
        int total = 0;
        for (Integer value : values) {
            if (value == null) {
                continue;
            } else if (strict && value < 0 || value > 1000) {
                total -= 1;
            } else {
                total += value;
            }
        }
        values.forEach(item -> {
            if (item != null && item > 10) {
                System.out.println(item);
            }
        });
        switch (total) {
            case 0:
                return 0;
            case 1:
                return 1;
            default:
                return total;
        }
    }

    /** Mentions Runtime.exec and unserialize( in a comment only. */
    public String helpText() {
        return "call Runtime.getRuntime().exec(cmd) only in tests";
    }

    public int fact(int n) {
        return n <= 1 ? 1 : n * fact(n - 1);
    }
}
