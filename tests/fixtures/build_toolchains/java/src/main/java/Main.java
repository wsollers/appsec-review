import org.apache.commons.collections.map.HashedMap;

public class Main {
    public static void main(String[] args) {
        HashedMap map = new HashedMap();
        map.put("name", "appsec fixture");
        System.out.println(map.get("name"));
    }
}
