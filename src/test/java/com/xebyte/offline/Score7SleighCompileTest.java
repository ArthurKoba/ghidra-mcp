package com.xebyte.offline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.Test;

public class Score7SleighCompileTest {

    @Test
    public void score7ProcessorDefinitionCompilesWithBundledGhidraSleigh() throws Exception {
        Path ghidraRoot = findCiGhidraRoot();
        assumeTrue(
            "Ghidra distribution not present; SCORE7 CLI compile check is CI-only",
            ghidraRoot != null
        );

        Path sleigh = ghidraRoot.resolve("support").resolve("sleigh");
        Path source = Path.of(
            "ghidra_processors",
            "SCORE7",
            "data",
            "languages",
            "SCORE7.slaspec"
        ).toAbsolutePath();

        assertTrue("support/sleigh must exist", Files.isExecutable(sleigh));
        assertTrue("SCORE7.slaspec must exist", Files.isRegularFile(source));

        Path tempDir = Files.createTempDirectory("score7-sleigh-test-");
        Path output = tempDir.resolve("SCORE7.sla");
        try {
            Process process = new ProcessBuilder(
                sleigh.toString(),
                source.toString(),
                output.toString()
            ).redirectErrorStream(true).start();

            ByteArrayOutputStream console = new ByteArrayOutputStream();
            try (InputStream input = process.getInputStream()) {
                input.transferTo(console);
            }
            int exit = process.waitFor();

            assertEquals(
                "SCORE7 SLEIGH compiler output:\n" + console.toString(),
                0,
                exit
            );
            assertTrue(
                "SCORE7.sla must be non-empty",
                Files.isRegularFile(output) && Files.size(output) > 0
            );
        }
        finally {
            Files.deleteIfExists(output);
            Files.deleteIfExists(tempDir);
        }
    }

    private static Path findCiGhidraRoot() throws Exception {
        Path root = Path.of("/tmp/ghidra");
        if (!Files.isDirectory(root)) {
            return null;
        }

        try (DirectoryStream<Path> entries = Files.newDirectoryStream(root, "ghidra_*")) {
            for (Path entry : entries) {
                if (Files.isDirectory(entry)) {
                    return entry;
                }
            }
        }
        return null;
    }
}
