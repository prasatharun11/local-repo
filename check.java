import org.jsoup.Jsoup;
import org.jsoup.safety.Whitelist;

public class JSONSanitizer {

    public static String customSanitizeScripts(String input) {
        // If the input is a number, return it as a string
        if (input.matches("\\d+")) {
            return input;
        }

        // Create a custom whitelist, allowing specific tags and attributes
        Whitelist whitelist = new Whitelist()
                .addTags("script", "a", "i", "link", "meta")
                .addAttributes("a", "onclick", "onchange", "href", "target")
                .addAttributes("script", "adDetCode", "adDetDispTxt", "adJustCode")
                .addAttributes("meta", "clm_det_cont_type", "mm-module", "app-module");

        // Sanitize the input using the whitelist
        return Jsoup.clean(input, whitelist);
    }

    public static void main(String[] args) {
        String unsanitizedInput = "<a href='https://example.com' onclick='alert(1)'>Click me</a><script>alert('Hello');</script>";
        String sanitizedOutput = customSanitizeScripts(unsanitizedInput);
        System.out.println(sanitizedOutput);
    }
}