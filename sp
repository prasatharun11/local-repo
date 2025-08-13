import java.nio.file.Path;
import java.nio.file.Paths;

public class SafePathUtil {

    private static final Path BASE_DIR = Paths.get("/var/app/data").toAbsolutePath().normalize();

    /**
     * Sanitizes a file path string so it always stays within BASE_DIR.
     * Removes any absolute path or directory traversal attempts.
     */
    public static String getSafePath(String inputPath) {
        if (inputPath == null || inputPath.trim().isEmpty()) {
            throw new IllegalArgumentException("Invalid path");
        }

        // Extract only the file name to avoid traversal
        Path safePath = BASE_DIR.resolve(Paths.get(inputPath).getFileName()).normalize();

        // Final security check
        if (!safePath.startsWith(BASE_DIR)) {
            throw new SecurityException("Path escapes base directory");
        }

        return safePath.toString();
    }

    public static void main(String[] args) {
        String unsafe = "../../etc/passwd";
        String safe = getSafePath(unsafe);
        System.out.println(safe); // /var/app/data/passwd
    }
}