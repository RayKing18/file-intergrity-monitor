import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;

/**
 * File Integrity Monitor (FIM)
 * Detects unauthorized file changes using SHA-256 cryptographic hashing.
 * 
 * Usage:
 *   java FileIntegrityMonitor --init  [directory] [baseline]
 *   java FileIntegrityMonitor --check [directory] [baseline]
 */
public class FileIntegrityMonitor {

    private static final int BUFFER_SIZE = 65536;

    public static void main(String[] args) {

        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        String mode = args[0];
        String targetDir = args.length > 1 ? args[1] : ".";
        String baselineFile = args.length > 2 ? args[2] : "baseline.properties";

        Path targetPath = Paths.get(targetDir);

        switch (mode) {
            case "--init":
                System.out.println("[*] Init mode selected.");
                System.out.println("[*] Target directory: " + targetPath.toAbsolutePath());
                
                if (!Files.exists(targetPath)) {
                    System.err.println("[x] Error: Target path '" + targetPath + "' does not exist.");
                    System.exit(1);
                }

                System.out.println("[*] Scanning directory and calculating SHA-256 hashes...\n");
                Map<String, String> fileHashes = scanDirectory(targetPath);
                
                System.out.println("--- DISCOVERED FILES AND HASHES (" + fileHashes.size() + ") ---");
                for (Map.Entry<String, String> entry : fileHashes.entrySet()) {
                    System.out.println("File: " + entry.getKey());
                    System.out.println("Hash: " + entry.getValue());
                    System.out.println();
                }
                break;

            case "--check":
                System.out.println("[*] Check mode selected.");
                System.out.println("[*] Target directory: " + targetPath.toAbsolutePath());
                System.out.println("[*] Baseline file:    " + baselineFile);
                break;

            default:
                System.err.println("[x] Unknown mode: " + mode);
                printUsage();
                System.exit(1);
        }
    }

    /**
     * Recursively scans a target directory and computes the SHA-256 hash for each file.
     *
     * @param targetDir Directory to recursively scan
     * @return Sorted map of relative file paths to their hex SHA-256 hashes
     */
    public static Map<String, String> scanDirectory(Path targetDir) {
        Map<String, String> fileHashes = new TreeMap<>();

        // Handle single file input gracefully
        if (Files.isRegularFile(targetDir)) {
            String hash = calculateSHA256(targetDir);
            if (hash != null) {
                fileHashes.put(targetDir.getFileName().toString(), hash);
            }
            return fileHashes;
        }

        // Walk directory tree recursively using Java NIO Streams
        try (Stream<Path> stream = Files.walk(targetDir)) {
            stream.filter(Files::isRegularFile)
                  .forEach(file -> {
                      // Convert absolute file path to a relative path from targetDir
                      String relativePath = targetDir.relativize(file).toString();
                      String hash = calculateSHA256(file);
                      if (hash != null) {
                          fileHashes.put(relativePath, hash);
                      }
                  });
        } catch (IOException e) {
            System.err.println("[x] Error scanning directory tree: " + e.getMessage());
        }

        return fileHashes;
    }

    /**
     * Computes the SHA-256 hash of a file using chunked stream I/O.
     */
    public static String calculateSHA256(Path filePath) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            try (InputStream is = new BufferedInputStream(Files.newInputStream(filePath))) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            byte[] hashBytes = digest.digest();

            StringBuilder hexString = new StringBuilder(hashBytes.length * 2);
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            System.err.println("[x] SHA-256 algorithm not available on this JVM: " + e.getMessage());
            return null;
        } catch (AccessDeniedException e) {
            System.err.println("[!] Permission denied reading: " + filePath);
            return null;
        } catch (IOException e) {
            System.err.println("[!] Failed to read file " + filePath + ": " + e.getMessage());
            return null;
        }
    }

    private static void printUsage() {
        System.out.println("=============================================");
        System.out.println("  File Integrity Monitor (FIM)");
        System.out.println("  SHA-256 Host-Based Detection Tool");
        System.out.println("=============================================");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java FileIntegrityMonitor --init  [dir] [baseline]");
        System.out.println("  java FileIntegrityMonitor --check [dir] [baseline]");
    }
}
