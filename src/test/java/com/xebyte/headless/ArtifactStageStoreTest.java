package com.xebyte.headless;

import junit.framework.TestCase;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

public class ArtifactStageStoreTest extends TestCase {

    public void testChunkedStageRoundTripAndCleanup() throws Exception {
        Path root = Files.createTempDirectory("artifact-stage-test");
        ArtifactStageStore store = new ArtifactStageStore(root, 1024 * 1024, 64 * 1024);

        byte[] payload = "hello-artifact-stage".getBytes(StandardCharsets.UTF_8);
        String sha256 = sha256(payload);

        Map<String, Object> begun = store.begin("Sofia", payload.length, sha256);
        String stageId = (String) begun.get("stage_id");

        byte[] first = java.util.Arrays.copyOfRange(payload, 0, 5);
        byte[] second = java.util.Arrays.copyOfRange(payload, 5, payload.length);

        Map<String, Object> afterFirst = store.write(
            stageId, 0, Base64.getEncoder().encodeToString(first));
        assertEquals(5L, ((Number) afterFirst.get("next_offset")).longValue());

        Map<String, Object> afterSecond = store.write(
            stageId, 5, Base64.getEncoder().encodeToString(second));
        assertEquals((long) payload.length,
            ((Number) afterSecond.get("next_offset")).longValue());

        Map<String, Object> finished = store.finish(stageId);
        assertEquals(Boolean.TRUE, finished.get("committed"));
        assertEquals(sha256, finished.get("sha256"));

        Path staged = Path.of((String) finished.get("path"));
        assertTrue(Files.isRegularFile(staged));
        assertEquals("Sofia", staged.getFileName().toString());
        assertTrue(java.util.Arrays.equals(payload, Files.readAllBytes(staged)));

        Map<String, Object> cancelled = store.cancel(stageId);
        assertEquals(Boolean.TRUE, cancelled.get("cancelled"));
        assertFalse(Files.exists(staged.getParent()));
    }

    public void testRejectsWrongOffsetAndChecksum() throws Exception {
        Path root = Files.createTempDirectory("artifact-stage-test");
        ArtifactStageStore store = new ArtifactStageStore(root, 1024 * 1024, 64 * 1024);

        byte[] payload = "abc".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> begun = store.begin(
            "firmware.bin", payload.length, sha256("xyz".getBytes(StandardCharsets.UTF_8)));
        String stageId = (String) begun.get("stage_id");

        try {
            store.write(stageId, 1, Base64.getEncoder().encodeToString(payload));
            fail("wrong offset should fail");
        } catch (java.io.IOException expected) {
            assertTrue(expected.getMessage().contains("offset mismatch"));
        }

        store.write(stageId, 0, Base64.getEncoder().encodeToString(payload));
        try {
            store.finish(stageId);
            fail("checksum mismatch should fail");
        } catch (java.io.IOException expected) {
            assertTrue(expected.getMessage().contains("SHA-256 mismatch"));
        } finally {
            store.cancel(stageId);
        }
    }

    private static String sha256(byte[] payload) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        StringBuilder out = new StringBuilder();
        for (byte value : digest.digest(payload)) {
            out.append(String.format("%02x", value & 0xff));
        }
        return out.toString();
    }
}
