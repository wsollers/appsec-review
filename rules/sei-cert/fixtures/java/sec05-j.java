// SEI CERT SEC05-J focused fixture.
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

class Reflector {
    Object readSecret(Object target) throws ReflectiveOperationException {
        Field field = target.getClass().getDeclaredField("secret");
        // cert: positive appsec-review.sei-cert.java.sec05-j.reflective-accessibility-increase
        field.setAccessible(true);
        return field.get(target);
    }

    void openAll(Method[] methods) {
        // cert: variant appsec-review.sei-cert.java.sec05-j.reflective-accessibility-increase
        AccessibleObject.setAccessible(methods, true);
    }

    boolean tryOpen(Method method) {
        // cert: variant appsec-review.sei-cert.java.sec05-j.reflective-accessibility-increase
        return method.trySetAccessible();
    }

    Object readPublic(Object target) throws ReflectiveOperationException {
        // cert: safe-alternative appsec-review.sei-cert.java.sec05-j.reflective-accessibility-increase
        return target.getClass().getField("name").get(target);
    }

    void restore(Field field) {
        // cert: near-miss appsec-review.sei-cert.java.sec05-j.reflective-accessibility-increase
        field.setAccessible(false);
    }
}
