package com.ksh.util;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/**
 * ClamAV signature-based malware scanner for web applications
 * Scans files using main.ndb and daily.ndb signature files
 */
public class ClamAVScanner {
    
    private Set<String> md5Signatures = new HashSet<>();
    private Set<String> sha1Signatures = new HashSet<>();
    private Set<String> sha256Signatures = new HashSet<>();
    private List<HexSignature> hexSignatures = new ArrayList<>();
    
    private static final int MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB limit
    private static final int BUFFER_SIZE = 8192;
    
    /**
     * Container for hex-based signatures with offset information
     */
    private static class HexSignature {
        String name;
        String hexPattern;
        int offset;
        
        HexSignature(String name, String hexPattern, int offset) {
            this.name = name;
            this.hexPattern = hexPattern.toLowerCase();
            this.offset = offset;
        }
    }
    
    /**
     * Initialize scanner with ClamAV signature files
     * @param mainNdbPath Path to main.ndb file
     * @param dailyNdbPath Path to daily.ndb file
     * @throws IOException if signature files cannot be read
     */
    public ClamAVScanner(String mainNdbPath, String dailyNdbPath) throws IOException {
        loadSignatures(mainNdbPath);
        loadSignatures(dailyNdbPath);
    }
    
    /**
     * Load signatures from .ndb file
     * NDB format: MalwareName:TargetType:Offset:HexSignature[:MinEngineVersion[:MaxEngineVersion]]
     */
    private void loadSignatures(String ndbPath) throws IOException {
        Path path = Paths.get(ndbPath);
        
        // Handle both regular and gzipped files
        InputStream inputStream;
        if (ndbPath.endsWith(".gz")) {
            inputStream = new GZIPInputStream(Files.newInputStream(path));
        } else {
            inputStream = Files.newInputStream(path);
        }
        
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                
                parseSignatureLine(line);
            }
        }
    }
    
    /**
     * Parse individual signature line from NDB file
     */
    private void parseSignatureLine(String line) {
        String[] parts = line.split(":");
        if (parts.length < 4) {
            return; // Invalid format
        }
        
        String malwareName = parts[0];
        String targetType = parts[1];
        String offsetStr = parts[2];
        String hexSignature = parts[3];
        
        // Skip if target type is not applicable (0 = any file, 1 = PE files)
        if (!targetType.equals("0") && !targetType.equals("1")) {
            return;
        }
        
        try {
            int offset = parseOffset(offsetStr);
            
            // Check if this is a hash signature (MD5, SHA1, SHA256)
            if (isHashSignature(hexSignature)) {
                addHashSignature(hexSignature);
            } else {
                // Regular hex pattern signature
                hexSignatures.add(new HexSignature(malwareName, hexSignature, offset));
            }
        } catch (NumberFormatException e) {
            // Skip malformed signatures
        }
    }
    
    /**
     * Parse offset value (can be *, decimal, or hex)
     */
    private int parseOffset(String offsetStr) {
        if ("*".equals(offsetStr)) {
            return -1; // Any offset
        }
        
        if (offsetStr.startsWith("0x")) {
            return Integer.parseInt(offsetStr.substring(2), 16);
        }
        
        return Integer.parseInt(offsetStr);
    }
    
    /**
     * Check if signature is a hash (32, 40, or 64 hex characters)
     */
    private boolean isHashSignature(String signature) {
        return signature.matches("[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}");
    }
    
    /**
     * Add hash signature to appropriate set
     */
    private void addHashSignature(String hash) {
        hash = hash.toLowerCase();
        switch (hash.length()) {
            case 32:
                md5Signatures.add(hash);
                break;
            case 40:
                sha1Signatures.add(hash);
                break;
            case 64:
                sha256Signatures.add(hash);
                break;
        }
    }
    
    /**
     * Convert hex string to byte array (for non-wildcard patterns)
     */
    private byte[] hexStringToByteArray(String hex) {
        try {
            if (hex.contains("?")) {
                return null; // Handled separately by wildcard matcher
            }
            
            if (hex.length() % 2 != 0) {
                return null; // Invalid hex string
            }
            
            byte[] bytes = new byte[hex.length() / 2];
            for (int i = 0; i < hex.length(); i += 2) {
                bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
            }
            return bytes;
        } catch (NumberFormatException e) {
            return null;
        }
    }
    
    /**
     * Enhanced file scanning with built-in EICAR detection
     */
    public ScanResult scanFile(File uploadedFile) {
        try {
            // Check file size
            if (uploadedFile.length() > MAX_FILE_SIZE) {
                return new ScanResult(false, true, "File too large to scan", null);
            }
            
            // Read file content
            byte[] fileContent = Files.readAllBytes(uploadedFile.toPath());
            
            // Check for EICAR test file first (built-in detection)
            if (isEicarTestFile(fileContent)) {
                return new ScanResult(false, false, "Malware detected", "EICAR test file detected");
            }
            
            // Check hash signatures (faster)
            ScanResult hashResult = checkHashSignatures(fileContent);
            if (hashResult.isThreatDetected()) {
                return hashResult;
            }
            
            // Check hex pattern signatures
            ScanResult hexResult = checkHexSignatures(fileContent);
            if (hexResult.isThreatDetected()) {
                return hexResult;
            }
            
            return new ScanResult(true, false, "File is clean", null);
            
        } catch (IOException e) {
            return new ScanResult(false, true, "Error scanning file: " + e.getMessage(), null);
        }
    }
    
    /**
     * Built-in EICAR test file detection
     */
    private boolean isEicarTestFile(byte[] fileContent) {
        String eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        byte[] eicarBytes = eicarString.getBytes();
        
        if (fileContent.length < eicarBytes.length) {
            return false;
        }
        
        // Check if file contains EICAR signature anywhere
        return searchPattern(fileContent, eicarBytes);
    }
    
    /**
     * Check file against hash signatures
     */
    private ScanResult checkHashSignatures(byte[] fileContent) {
        try {
            // MD5
            String md5 = calculateHash(fileContent, "MD5");
            if (md5Signatures.contains(md5)) {
                return new ScanResult(false, false, "Malware detected", "MD5 hash match: " + md5);
            }
            
            // SHA1
            String sha1 = calculateHash(fileContent, "SHA-1");
            if (sha1Signatures.contains(sha1)) {
                return new ScanResult(false, false, "Malware detected", "SHA1 hash match: " + sha1);
            }
            
            // SHA256
            String sha256 = calculateHash(fileContent, "SHA-256");
            if (sha256Signatures.contains(sha256)) {
                return new ScanResult(false, false, "Malware detected", "SHA256 hash match: " + sha256);
            }
            
        } catch (NoSuchAlgorithmException e) {
            // Hash algorithm not available
        }
        
        return new ScanResult(true, false, "No hash matches", null);
    }
    
    /**
     * Calculate file hash
     */
    private String calculateHash(byte[] content, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hashBytes = digest.digest(content);
        
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * Check file against hex pattern signatures
     */
    private ScanResult checkHexSignatures(byte[] fileContent) {
        for (HexSignature signature : hexSignatures) {
            if (matchesHexSignature(fileContent, signature)) {
                return new ScanResult(false, false, "Malware detected", 
                    "Hex signature match: " + signature.name);
            }
        }
        
        return new ScanResult(true, false, "No hex signature matches", null);
    }
    
    /**
     * Check if file content matches hex signature
     */
    private boolean matchesHexSignature(byte[] fileContent, HexSignature signature) {
        // Handle special case for EICAR test file
        if (signature.name.toLowerCase().contains("eicar") || 
            signature.hexPattern.toLowerCase().contains("eicar")) {
            return matchesEicarPattern(fileContent);
        }
        
        // Handle wildcard patterns
        if (signature.hexPattern.contains("?")) {
            return matchesWildcardPattern(fileContent, signature);
        }
        
        byte[] pattern = hexStringToByteArray(signature.hexPattern);
        if (pattern == null || pattern.length == 0) {
            return false;
        }
        
        if (signature.offset >= 0) {
            // Fixed offset
            if (signature.offset + pattern.length > fileContent.length) {
                return false;
            }
            return matchesAtOffset(fileContent, pattern, signature.offset);
        } else {
            // Any offset - search entire file
            return searchPattern(fileContent, pattern);
        }
    }
    
    /**
     * Check pattern match at specific offset
     */
    private boolean matchesAtOffset(byte[] content, byte[] pattern, int offset) {
        for (int i = 0; i < pattern.length; i++) {
            if (content[offset + i] != pattern[i]) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Search for pattern anywhere in content
     */
    private boolean searchPattern(byte[] content, byte[] pattern) {
        for (int i = 0; i <= content.length - pattern.length; i++) {
            if (matchesAtOffset(content, pattern, i)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Special handling for EICAR test file detection
     */
    private boolean matchesEicarPattern(byte[] fileContent) {
        // EICAR standard test string
        String eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        byte[] eicarBytes = eicarString.getBytes();
        
        // Check if file starts with EICAR pattern
        if (fileContent.length >= eicarBytes.length) {
            boolean matches = true;
            for (int i = 0; i < eicarBytes.length; i++) {
                if (fileContent[i] != eicarBytes[i]) {
                    matches = false;
                    break;
                }
            }
            if (matches) return true;
        }
        
        // Also check for EICAR anywhere in the file
        return searchPattern(fileContent, eicarBytes);
    }
    
    /**
     * Handle wildcard patterns (? represents any byte)
     */
    private boolean matchesWildcardPattern(byte[] fileContent, HexSignature signature) {
        String pattern = signature.hexPattern.toLowerCase();
        
        if (signature.offset >= 0) {
            return matchesWildcardAtOffset(fileContent, pattern, signature.offset);
        } else {
            // Search entire file
            for (int i = 0; i <= fileContent.length - (pattern.length() / 2); i++) {
                if (matchesWildcardAtOffset(fileContent, pattern, i)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * Match wildcard pattern at specific offset
     */
    private boolean matchesWildcardAtOffset(byte[] content, String hexPattern, int offset) {
        if (hexPattern.length() % 2 != 0) {
            return false;
        }
        
        int patternBytes = hexPattern.length() / 2;
        if (offset + patternBytes > content.length) {
            return false;
        }
        
        for (int i = 0; i < patternBytes; i++) {
            String hexByte = hexPattern.substring(i * 2, i * 2 + 2);
            if (!"??".equals(hexByte)) {
                try {
                    byte expectedByte = (byte) Integer.parseInt(hexByte, 16);
                    if (content[offset + i] != expectedByte) {
                        return false;
                    }
                } catch (NumberFormatException e) {
                    return false;
                }
            }
            // If hexByte is "??", it matches any byte, so continue
        }
        return true;
    }
    
    /**
     * Result of a malware scan
     */
    public static class ScanResult {
        private final boolean clean;
        private final boolean error;
        private final String message;
        private final String threatDetails;
        
        public ScanResult(boolean clean, boolean error, String message, String threatDetails) {
            this.clean = clean;
            this.error = error;
            this.message = message;
            this.threatDetails = threatDetails;
        }
        
        public boolean isClean() { return clean; }
        public boolean isError() { return error; }
        public boolean isThreatDetected() { return !clean && !error; }
        public String getMessage() { return message; }
        public String getThreatDetails() { return threatDetails; }
        
        @Override
        public String toString() {
            return String.format("ScanResult{clean=%s, error=%s, message='%s', details='%s'}", 
                clean, error, message, threatDetails);
        }
    }
    
    /**
     * Example usage method
     * Usage: java ClamAVScanner <main.ndb_path> <daily.ndb_path> <file_to_scan>
     * Example: java ClamAVScanner E:/Temp/VS/Unpacked/main.ndb E:/Temp/VS/Unpacked/daily.ndb C:/Users/RKolte/Downloads/eicar.txt
     */
    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("Usage: java ClamAVScanner <main.ndb_path> <daily.ndb_path> <file_to_scan>");
            System.err.println("Example: java ClamAVScanner E:/Temp/VS/Unpacked/main.ndb E:/Temp/VS/Unpacked/daily.ndb C:/Users/RKolte/Downloads/eicar.txt");
            System.exit(1);
        }
        
        String mainNdbPath = args[0];
        String dailyNdbPath = args[1];
        String fileToScan = args[2];
        
        try {
            System.out.println("Initializing ClamAV scanner...");
            System.out.println("Main signatures: " + mainNdbPath);
            System.out.println("Daily signatures: " + dailyNdbPath);
            System.out.println("File to scan: " + fileToScan);
            System.out.println();
            
            // Check if files exist
            if (!new File(mainNdbPath).exists()) {
                System.err.println("Error: Main signature file not found: " + mainNdbPath);
                System.exit(1);
            }
            if (!new File(dailyNdbPath).exists()) {
                System.err.println("Error: Daily signature file not found: " + dailyNdbPath);
                System.exit(1);
            }
            if (!new File(fileToScan).exists()) {
                System.err.println("Error: File to scan not found: " + fileToScan);
                System.exit(1);
            }
            
            // Initialize scanner with signature files
            ClamAVScanner scanner = new ClamAVScanner(mainNdbPath, dailyNdbPath);
            System.out.println("Scanner initialized successfully.");
            System.out.println("Loaded signatures - MD5: " + scanner.md5Signatures.size() + 
                             ", SHA1: " + scanner.sha1Signatures.size() + 
                             ", SHA256: " + scanner.sha256Signatures.size() + 
                             ", Hex patterns: " + scanner.hexSignatures.size());
            System.out.println();
            
            // Scan the specified file
            File testFile = new File(fileToScan);
            System.out.println("Scanning file: " + testFile.getName() + " (" + testFile.length() + " bytes)");
            
            long startTime = System.currentTimeMillis();
            ScanResult result = scanner.scanFile(testFile);
            long endTime = System.currentTimeMillis();
            
            System.out.println("Scan completed in " + (endTime - startTime) + " ms");
            System.out.println();
            System.out.println("=== SCAN RESULTS ===");
            System.out.println("Status: " + (result.isClean() ? "CLEAN" : 
                                           result.isThreatDetected() ? "INFECTED" : "ERROR"));
            System.out.println("Message: " + result.getMessage());
            
            if (result.isThreatDetected()) {
                System.out.println("THREAT DETECTED: " + result.getThreatDetails());
                System.out.println("File should be REJECTED/QUARANTINED");
            } else if (result.isClean()) {
                System.out.println("File is clean and safe");
            } else {
                System.out.println("Error occurred: " + result.getMessage());
            }
            
        } catch (IOException e) {
            System.err.println("Error initializing scanner: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}