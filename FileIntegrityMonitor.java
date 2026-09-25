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
        Path baselinePath = Paths.get(baselineFile);

        switch (mode) {
            case "--init":
                initBaseline(targetPath, baselinePath);
                break;

            case "--check":
                System.out.println("[*] Check mode selected.");
                System.out.println("[*] Target directory: " + targetPath.toAbsolutePath());
                System.out.println("[*] Baseline file:    " + baselinePath.toAbsolutePath());
                // TODO: Implemented in Stage 5
                break;

            default:
                System.err.println("[x] Unknown mode: " + mode);
                printUsage();
                System.exit(1);
        }
    }

    /**
     * Generates a baseline manifest file containing SHA-256 hashes of all files in targetDir.
     *
     * @param targetDir Directory to scan
     * @param baselinePath Output path for the baseline manifest
     */
    private static void initBaseline(Path targetDir, Path baselinePath) {
        System.out.println("[*] Generating baseline manifest...");
        System.out.println("[*] Target directory: " + targetDir.toAbsolutePath());

        if (!Files.exists(targetDir)) {
            System.err.println("[x] Error: Target path '" + targetDir + "' does not exist.");
            System.exit(1);
        }

        Map<String, String> fileHashes = scanDirectory(targetDir);

        // Properties is Java's standard key-value configuration and manifest container
        Properties props = new Properties();
        props.setProperty("metadata.timestamp", Instant.now().toString());
        props.setProperty("metadata.target", targetDir.toAbsolutePath().toString());
        props.setProperty("metadata.fileCount", String.valueOf(fileHashes.size()));

        for (Map.Entry<String, String> entry : fileHashes.entrySet()) {
            props.setProperty("hash." + entry.getKey(), entry.getValue());
        }

        // Save manifest using buffered I/O stream
        try (OutputStream out = new BufferedOutputStream(Files.newOutputStream(baselinePath))) {
            props.store(out, "FIM Security Baseline Manifest - SHA-256");
            System.out.println("[+] Success: Baseline generated with " + fileHashes.size() + " file signature(s).");
            System.out.println("[+] Manifest written to: " + baselinePath.toAbsolutePath());
        } catch (IOException e) {
            System.err.println("[x] Error writing baseline file: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Recursively scans a target directory and computes the SHA-256 hash for each file.
     */
    public static Map<String, String> scanDirectory(Path targetDir) {
        Map<String, String> fileHashes = new TreeMap<>();

        if (Files.isRegularFile(targetDir)) {
            String hash = calculateSHA256(targetDir);
            if (hash != null) {
                fileHashes.put(targetDir.getFileName().toString(), hash);
            }
            return fileHashes;
        }

        try (Stream<Path> stream = Files.walk(targetDir)) {
            stream.filter(Files::isRegularFile)
                  .forEach(file -> {
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
