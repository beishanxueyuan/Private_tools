import java.util.Arrays;
import java.util.List;

public class TestCode {
    public static void main(String[] args) {
        String urlWhitelistText = "example.com";
        
        // 拆分字符串并转换为List
        List<String> urlWhitelist = Arrays.asList(urlWhitelistText.split("\\s*,\\s*"));

        // 输出结果
            System.out.println(urlWhitelist.contains("example.com"));
    }
}