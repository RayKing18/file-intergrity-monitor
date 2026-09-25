import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;

public class FileIntegrityMonitor {

    // Read files in 64 KB chunks to avoid running out of memory on large files
    private static final int BUFFER_SIZE = 65536;

    public static void main(String[] args) {

        // ── Step 1: Check if the user provided at least one argument ──
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        // ── Step 2: Read the mode (--init or --check) ──
        String mode = args[0];

        // ── Step 3: Read optional arguments with defaults ──
        // If the user didn't specify a directory, use "." (current folder)
        String targetDir = args.length > 1 ? args[1] : ".";

        // If the user didn't specify a baseline file, use "baseline.properties"
        String baselineFile = args.length > 2 ? args[2] : "baseline.properties";

        // ── Step 4: Route to the correct function based on mode ──
        switch (mode) {
            case "--init":
                System.out.println("[*] Init mode selected.");
                System.out.println("[*] Target directory: " + targetDir);
                System.out.println("[*] Baseline file:    " + baselineFile);
                // TODO: Call initBaseline() in Stage 4
                break;

            case "--check":
                System.out.println("[*] Check mode selected.");
                System.out.println("[*] Target directory: " + targetDir);
                System.out.println("[*] Baseline file:    " + baselineFile);
                // TODO: Call checkIntegrity() in Stage 5
                break;

            default:
                // If the user typed something we don't recognize
                System.err.println("[x] Unknown mode: " + mode);
                printUsage();
                System.exit(1);
        }
    }

}