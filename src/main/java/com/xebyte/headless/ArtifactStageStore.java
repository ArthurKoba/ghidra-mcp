package com.xebyte.headless;

import com.xebyte.core.SecurityConfig;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

/**
 * Internal staging area for artifacts pushed by the orchestrator/bridge.
 *
 * <p>The bridge transfers bytes through this private boundary without exposing
 * Ghidra project storage. Inbound files use chunked staging; exported files can
 * be read back in bounded chunks from the configured file root.</p>
 */
public final class ArtifactStageStore {

    private static final long DEFAULT_MAX_BYTES = 8L * 1024 * 1024 * 1024;
    private static final int DEFAULT_CHUNK_BYTES = 1024 * 1024;

    private final Path fileRoot;
    private final Path root;
    private final long maxBytes;
    private final int chunkBytes;

    public ArtifactStageStore(Path fileRoot) throws IOException {
        this(fileRoot, envLong("GHIDRA_MCP_STAGE_MAX_BYTES", DEFAULT_MAX_BYTES),
            envInt("GHIDRA_MCP_STAGE_CHUNK_BYTES", DEFAULT_CHUNK_BYTES));
    }

    ArtifactStageStore(Path fileRoot, long maxBytes, int chunkBytes) throws IOException {
        if (fileRoot == null) {
            throw new IOException("GHIDRA_MCP_FILE_ROOT is required for artifact staging");
        }
        if (maxBytes <= 0) {
            throw new IOException("artifact staging max bytes must be positive");
        }
        if (chunkBytes < 64 * 1024 || chunkBytes > 8 * 1024 * 1024) {
            throw new IOException("artifact staging chunk size must be between 64 KiB and 8 MiB");
        }
        this.fileRoot = fileRoot.toAbsolutePath().normalize();
        this.root = this.fileRoot.resolve(".koba-stage").normalize();
        if (!this.root.startsWith(this.fileRoot)) {
            throw new IOException("artifact staging root escapes file root");
        }
        Files.createDirectories(this.root);
        this.maxBytes = maxBytes;
        this.chunkBytes = chunkBytes;
    }

    public static ArtifactStageStore fromSecurityConfig() throws IOException {
        SecurityConfig security = SecurityConfig.getInstance();
        String fileRoot = security.getFileRoot();
        if (fileRoot == null || fileRoot.isBlank()) {
            throw new IOException("GHIDRA_MCP_FILE_ROOT is not configured");
        }
        Path resolved = security.resolveWithinFileRoot(fileRoot);
        if (resolved == null) {
            throw new IOException("configured file root could not be resolved");
        }
        return new ArtifactStageStore(resolved);
    }

    public synchronized Map<String, Object> begin(
            String name,
            long expectedSize,
            String expectedSha256) throws IOException {

        String cleanName = HeadlessPaths.safeBasename(name == null ? "" : name.trim());
        String invalid = HeadlessPaths.validateFilename(cleanName);
        if (cleanName.isEmpty() || invalid != null) {
            throw new IOException("invalid artifact name");
        }
        if (expectedSize < 0 || expectedSize > maxBytes) {
            throw new IOException("artifact size exceeds configured staging limit");
        }

        String digest = normalizeSha256(expectedSha256);
        String stageId = UUID.randomUUID().toString();
        Path dir = stageDir(stageId);
        Files.createDirectory(dir);
        Path part = dir.resolve(cleanName + ".part");
        Files.createFile(part);

        Properties meta = new Properties();
        meta.setProperty("name", cleanName);
        meta.setProperty("expected_size", Long.toString(expectedSize));
        meta.setProperty("expected_sha256", digest);
        meta.setProperty("state", "open");
        storeMeta(dir, meta);

        return status(stageId, meta, part, false);
    }

    public synchronized Map<String, Object> write(
            String stageId,
            long offset,
            String dataBase64) throws IOException {

        Path dir = stageDir(stageId);
        Properties meta = loadMeta(dir);
        requireOpen(meta);

        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(dataBase64 == null ? "" : dataBase64);
        } catch (IllegalArgumentException e) {
            throw new IOException("data_base64 is invalid", e);
        }
        if (payload.length == 0) {
            throw new IOException("artifact stage chunk must not be empty");
        }
        if (payload.length > chunkBytes) {
            throw new IOException("artifact stage chunk exceeds configured chunk size");
        }

        Path part = openPartPath(dir, meta);
        long current = Files.size(part);
        long expected = parseLong(meta, "expected_size");
        if (offset != current) {
            throw new IOException("offset mismatch: expected " + current + ", received " + offset);
        }
        if (current + payload.length > expected) {
            throw new IOException("chunk exceeds declared artifact size");
        }

        try (FileOutputStream out = new FileOutputStream(part.toFile(), true)) {
            out.write(payload);
            out.flush();
            out.getFD().sync();
        }

        return status(stageId, meta, part, false);
    }

    public synchronized Map<String, Object> finish(String stageId) throws IOException {
        Path dir = stageDir(stageId);
        Properties meta = loadMeta(dir);

        if ("completed".equals(meta.getProperty("state"))) {
            Path completed = dir.resolve(meta.getProperty("name"));
            if (!Files.isRegularFile(completed)) {
                throw new IOException("completed artifact stage is missing");
            }
            return status(stageId, meta, completed, true);
        }

        requireOpen(meta);
        Path part = openPartPath(dir, meta);
        long expected = parseLong(meta, "expected_size");
        long actual = Files.size(part);
        if (actual != expected) {
            throw new IOException("artifact stage incomplete: received " + actual + " of " + expected);
        }

        String actualSha256 = sha256(part);
        String expectedSha256 = meta.getProperty("expected_sha256", "");
        if (!expectedSha256.isEmpty() && !expectedSha256.equals(actualSha256)) {
            throw new IOException(
                "artifact SHA-256 mismatch: expected " + expectedSha256 + ", found " + actualSha256);
        }

        Path completed = dir.resolve(meta.getProperty("name")).normalize();
        if (!completed.startsWith(dir)) {
            throw new IOException("artifact stage name escapes session directory");
        }
        try {
            Files.move(part, completed, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            Files.move(part, completed);
        }

        meta.setProperty("state", "completed");
        meta.setProperty("actual_sha256", actualSha256);
        storeMeta(dir, meta);

        return status(stageId, meta, completed, true);
    }

    public synchronized Map<String, Object> readFile(
            String path,
            long offset,
            int length) throws IOException {

        if (path == null || path.isBlank()) {
            throw new IOException("artifact path is required");
        }
        if (offset < 0) {
            throw new IOException("offset must be non-negative");
        }
        if (length <= 0 || length > chunkBytes) {
            throw new IOException(
                "length must be between 1 and configured artifact chunk size");
        }

        Path requested = Path.of(path.trim());
        Path candidate = requested.isAbsolute()
            ? requested.normalize()
            : fileRoot.resolve(requested).normalize();

        if (!candidate.startsWith(fileRoot)) {
            throw new IOException("artifact path is outside configured file root");
        }
        if (!Files.isRegularFile(candidate)) {
            throw new IOException("artifact file does not exist");
        }

        Path realRoot = fileRoot.toRealPath();
        Path realFile = candidate.toRealPath();
        if (!realFile.startsWith(realRoot)) {
            throw new IOException("artifact path resolves outside configured file root");
        }

        long size = Files.size(realFile);
        if (offset > size) {
            throw new IOException("offset exceeds artifact file size");
        }

        int toRead = (int) Math.min((long) length, size - offset);
        byte[] payload = new byte[toRead];
        int read = 0;
        try (InputStream in = Files.newInputStream(realFile)) {
            long skipped = 0;
            while (skipped < offset) {
                long delta = in.skip(offset - skipped);
                if (delta <= 0) {
                    throw new IOException("unable to seek artifact file");
                }
                skipped += delta;
            }
            while (read < toRead) {
                int delta = in.read(payload, read, toRead - read);
                if (delta < 0) {
                    break;
                }
                read += delta;
            }
        }

        if (read != payload.length) {
            payload = java.util.Arrays.copyOf(payload, read);
        }
        long nextOffset = offset + read;

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("path", realFile.toAbsolutePath().toString());
        out.put("offset", offset);
        out.put("bytes_read", read);
        out.put("next_offset", nextOffset);
        out.put("size_bytes", size);
        out.put("eof", nextOffset >= size);
        out.put("data_base64", Base64.getEncoder().encodeToString(payload));
        return out;
    }

    public synchronized Map<String, Object> deleteFile(String path) throws IOException {
        if (path == null || path.isBlank()) {
            throw new IOException("artifact path is required");
        }
        Path requested = Path.of(path.trim());
        Path candidate = requested.isAbsolute()
            ? requested.normalize()
            : fileRoot.resolve(requested).normalize();
        if (!candidate.startsWith(fileRoot)) {
            throw new IOException("artifact path is outside configured file root");
        }
        if (!Files.isRegularFile(candidate)) {
            throw new IOException("artifact file does not exist");
        }
        Path realRoot = fileRoot.toRealPath();
        Path realFile = candidate.toRealPath();
        if (!realFile.startsWith(realRoot)) {
            throw new IOException("artifact path resolves outside configured file root");
        }
        Files.delete(realFile);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("path", realFile.toAbsolutePath().toString());
        out.put("deleted", true);
        return out;
    }

    public synchronized Map<String, Object> cancel(String stageId) throws IOException {
        Path dir = stageDir(stageId);
        if (!Files.exists(dir)) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("stage_id", stageId);
            out.put("already_absent", true);
            return out;
        }
        try (var paths = Files.walk(dir)) {
            paths.sorted((a, b) -> b.compareTo(a)).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException e) {
                    throw new StageDeleteRuntimeException(e);
                }
            });
        } catch (StageDeleteRuntimeException e) {
            throw e.ioException;
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("stage_id", stageId);
        out.put("cancelled", true);
        return out;
    }

    private Map<String, Object> status(
            String stageId,
            Properties meta,
            Path file,
            boolean completed) throws IOException {

        long expected = parseLong(meta, "expected_size");
        long received = Files.exists(file) ? Files.size(file) : 0L;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("stage_id", stageId);
        out.put("name", meta.getProperty("name"));
        out.put("expected_size", expected);
        out.put("bytes_received", received);
        out.put("next_offset", received);
        out.put("remaining_bytes", Math.max(0L, expected - received));
        out.put("complete", received == expected);
        out.put("committed", completed);
        out.put("chunk_bytes", chunkBytes);
        if (completed) {
            out.put("path", file.toAbsolutePath().toString());
            out.put("sha256", meta.getProperty("actual_sha256", ""));
        }
        return out;
    }

    private Path stageDir(String stageId) throws IOException {
        String normalized;
        try {
            normalized = UUID.fromString(stageId == null ? "" : stageId.trim()).toString();
        } catch (IllegalArgumentException e) {
            throw new IOException("invalid stage_id", e);
        }
        Path dir = root.resolve(normalized).normalize();
        if (!dir.startsWith(root)) {
            throw new IOException("invalid stage_id");
        }
        return dir;
    }

    private static String normalizeSha256(String value) throws IOException {
        String digest = value == null ? "" : value.trim().toLowerCase();
        if (digest.isEmpty()) {
            return "";
        }
        if (!digest.matches("[0-9a-f]{64}")) {
            throw new IOException("expected_sha256 must be a 64-character hexadecimal digest");
        }
        return digest;
    }

    private static long parseLong(Properties meta, String key) throws IOException {
        try {
            return Long.parseLong(meta.getProperty(key, ""));
        } catch (NumberFormatException e) {
            throw new IOException("artifact stage metadata is invalid", e);
        }
    }

    private static void requireOpen(Properties meta) throws IOException {
        if (!"open".equals(meta.getProperty("state"))) {
            throw new IOException("artifact stage is not open");
        }
    }

    private static Path openPartPath(Path dir, Properties meta) throws IOException {
        Path part = dir.resolve(meta.getProperty("name") + ".part").normalize();
        if (!part.startsWith(dir) || !Files.isRegularFile(part)) {
            throw new IOException("artifact stage bytes are missing");
        }
        return part;
    }

    private static Properties loadMeta(Path dir) throws IOException {
        Path file = dir.resolve("stage.properties");
        if (!Files.isRegularFile(file)) {
            throw new IOException("artifact stage does not exist");
        }
        Properties meta = new Properties();
        try (InputStream in = new FileInputStream(file.toFile())) {
            meta.load(in);
        }
        return meta;
    }

    private static void storeMeta(Path dir, Properties meta) throws IOException {
        Path file = dir.resolve("stage.properties");
        try (FileOutputStream out = new FileOutputStream(file.toFile())) {
            meta.store(out, "koba artifact stage");
            out.flush();
            out.getFD().sync();
        }
    }

    private static String sha256(Path path) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 is unavailable", e);
        }
        try (InputStream in = Files.newInputStream(path)) {
            byte[] buffer = new byte[1024 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        StringBuilder out = new StringBuilder(64);
        for (byte value : digest.digest()) {
            out.append(String.format("%02x", value & 0xff));
        }
        return out.toString();
    }

    private static long envLong(String name, long fallback) {
        String raw = System.getenv(name);
        if (raw == null || raw.isBlank()) return fallback;
        try {
            return Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static int envInt(String name, int fallback) {
        String raw = System.getenv(name);
        if (raw == null || raw.isBlank()) return fallback;
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static final class StageDeleteRuntimeException extends RuntimeException {
        final IOException ioException;
        StageDeleteRuntimeException(IOException ioException) {
            super(ioException);
            this.ioException = ioException;
        }
    }
}
