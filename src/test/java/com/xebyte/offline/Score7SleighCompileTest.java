package com.xebyte.offline;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import ghidra.pcodeCPort.slgh_compile.SleighCompile;
import ghidra.sleigh.grammar.Location;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public class Score7SleighCompileTest {

    @Test
    public void score7ProcessorDefinitionCompilesWithGhidraSleigh() throws Exception {
        Path source = Path.of(
            "ghidra_processors",
            "SCORE7",
            "data",
            "languages",
            "SCORE7.slaspec"
        ).toAbsolutePath();

        assertTrue("SCORE7.slaspec must exist", Files.isRegularFile(source));

        Path tempDir = Files.createTempDirectory("score7-sleigh-test-");
        Path output = tempDir.resolve("SCORE7.sla");
        try {
            CapturingCompile compiler = new CapturingCompile();
            int result = compiler.run_compilation(
                source.toString(),
                output.toString()
            );

            assertEquals(
                "SCORE7 SLEIGH compile failed:\n" +
                    String.join("\n", compiler.diagnostics),
                0,
                result
            );
            assertEquals(
                "SCORE7 SLEIGH errors:\n" +
                    String.join("\n", compiler.diagnostics),
                0,
                compiler.numErrors()
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

    private static final class CapturingCompile extends SleighCompile {
        private final List<String> diagnostics = new ArrayList<>();

        @Override
        public void reportError(Location location, String message) {
            diagnostics.add("ERROR " + location + " :: " + message);
            super.reportError(location, message);
        }

        @Override
        public void reportError(Location location, String message, Throwable throwable) {
            diagnostics.add(
                "ERROR " + location + " :: " + message + " :: " + throwable
            );
            super.reportError(location, message, throwable);
        }

        @Override
        public void reportWarning(Location location, String message) {
            diagnostics.add("WARN " + location + " :: " + message);
            super.reportWarning(location, message);
        }
    }
}
