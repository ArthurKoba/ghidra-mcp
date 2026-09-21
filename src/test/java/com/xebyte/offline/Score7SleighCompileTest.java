package com.xebyte.offline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
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

    @Test
    public void score7PacketWideConstructorsRequireAlignedPacketPhase() throws Exception {
        Path source = Path.of(
            "ghidra_processors",
            "SCORE7",
            "data",
            "languages",
            "SCORE7.slaspec"
        ).toAbsolutePath();

        List<String> lines = Files.readAllLines(source);
        List<String> rootConstructors = lines.stream()
            .filter(line -> line.startsWith(":") && !line.startsWith(":^instruction"))
            .toList();

        assertEquals("unexpected SCORE7 root-constructor count", 327, rootConstructors.size());
        assertTrue(
            "every real instruction constructor must be below the decode wrapper",
            rootConstructors.stream().allMatch(line -> line.contains("decode_phase=1"))
        );

        List<String> packetWideConstructors = rootConstructors.stream()
            .filter(line -> line.contains("p_lo="))
            .toList();
        assertEquals(
            "unexpected SCORE7 packet-wide constructor count",
            220,
            packetWideConstructors.size()
        );
        assertTrue(
            "32-bit/PCE/parity constructors must not start from PC+2",
            packetWideConstructors.stream().allMatch(line -> line.contains("packet_half=0"))
        );
        assertTrue(
            "root wrapper must derive the transient packet phase from inst_start",
            lines.stream().anyMatch(line ->
                line.contains(":^instruction is decode_phase=0 & instruction")
            )
        );
        assertTrue(
            "root wrapper must derive PC bit 1 before recursive decode",
            lines.stream().anyMatch(line ->
                line.contains("packet_half = (inst_start >> 1) $and 1")
            )
        );
    }

    @Test
    public void score7AbiReturnsUseReturnPcode() throws Exception {
        Path source = Path.of(
            "ghidra_processors",
            "SCORE7",
            "data",
            "languages",
            "SCORE7.slaspec"
        ).toAbsolutePath();

        List<String> lines = Files.readAllLines(source);
        assertTrue(
            "32-bit br r3 must be modeled as an ABI return",
            lines.stream().anyMatch(line ->
                line.startsWith(":br r3 is ") && line.contains("{ return [r3]; }")
            )
        );
        assertTrue(
            "16-bit br! r3 must be modeled as an ABI return",
            lines.stream().anyMatch(line ->
                line.startsWith(":br! r3 is ") && line.contains("{ return [r3]; }")
            )
        );
        assertTrue(
            "generic indirect br must remain available for non-r3 targets",
            lines.stream().anyMatch(line ->
                line.startsWith(":br ra32 is ") && line.contains("{ goto [ra32]; }")
            )
        );
        assertTrue(
            "generic compact indirect br! must remain available for non-r3 targets",
            lines.stream().anyMatch(line ->
                line.startsWith(":br! ra16 is ") && line.contains("{ goto [ra16]; }")
            )
        );
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
