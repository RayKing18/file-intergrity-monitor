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

    // Read files in 64 KB chunks to avoid running out of memory on large files
    private static final int BUFFER_SIZE = 65536;

    public static void main(String[] args) {

        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        String mode = args[0];
        String targetDir = args.length > 1 ? args[1] : ".";
        String baselineFile = args.length > 2 ? args[2] : "baseline.properties";

        switch (mode) {
            case "--init":
                System.out.println("[*] Init mode selected.");
                System.out.println("[*] Target directory: " + targetDir);
                System.out.println("[*] Baseline file:    " + baselineFile);
                // Testing our hash function directly on a single file if target is a file
                Path path = Paths.get(targetDir);
                if (Files.isRegularFile(path)) {
                    System.out.println("[*] Hashing single file: " + path.getFileName());
                    String hash = calculateSHA256(path);
                    System.out.println("[+] SHA-256: " + hash);
                }
                break;

            case "--check":
                System.out.println("[*] Check mode selected.");
                System.out.println("[*] Target directory: " + targetDir);
                System.out.println("[*] Baseline file:    " + baselineFile);
                break;

            default:
                System.err.println("[x] Unknown mode: " + mode);
                printUsage();
                System.exit(1);
        }
    }

    /**
     * Computes the SHA-256 hash of a file.
     * Uses streaming I/O with a 64KB buffer for memory efficiency.
     *
     * @param filePath Path to the file to hash
     * @return 64-character lowercase hex string, or null if reading fails
     */
    public static String calculateSHA256(Path filePath) {
        try {
            // 1. Initialize the SHA-256 cryptographic engine
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // 2. Stream the file in 64 KB chunks using try-with-resources
            try (InputStream is = new BufferedInputStream(Files.newInputStream(filePath))) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    // Feed each chunk into the digest
                    digest.update(buffer, 0, bytesRead);
                }
            }

            // 3. Complete the hash computation (produces 32 raw bytes)
            byte[] hashBytes = digest.digest();

            // 4. Convert 32 raw bytes into a 64-character hexadecimal string
            StringBuilder hexString = new StringBuilder(hashBytes.length * 2);
            for (byte b : hashBytes) {
                // %02x formats byte as a 2-digit zero-padded lowercase hex value
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

    /**
     * Prints instructions for how to use this tool.
     */
    private static void printUsage() {
        System.out.println("=============================================");
        System.out.println("  File Integrity Monitor (FIM)");
        System.out.println("  SHA-256 Host-Based Detection Tool");
        System.out.println("=============================================");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java FileIntegrityMonitor --init  [dir/file] [baseline]");
        System.out.println("  java FileIntegrityMonitor --check [dir]      [baseline]");
        System.out.println();
        System.out.println("Arguments:");
        System.out.println("  dir/file  Directory or file to process (default: current dir)");
        System.out.println("  baseline  Baseline file path (default: baseline.properties)");
    }
}