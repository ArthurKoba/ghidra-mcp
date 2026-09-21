package com.xebyte.offline;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.pcodeCPort.slgh_compile.SleighCompile;
import ghidra.pcodeCPort.slgh_compile.SleighCompileOptions;
import ghidra.sleigh.grammar.Location;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Score7SleighCompileTest {

    @TempDir
    Path tempDir;

    @Test
    void score7ProcessorDefinitionCompilesWithGhidraSleigh() throws Exception {
        Path source = Path.of(
            "ghidra_processors",
            "SCORE7",
            "data",
            "languages",
            "SCORE7.slaspec"
        ).toAbsolutePath();

        assertTrue(Files.isRegularFile(source), "SCORE7.slaspec must exist");

        Path output = tempDir.resolve("SCORE7.sla");
        SleighCompileOptions options = SleighCompileOptions.parse(
            new String[] { source.toString(), output.toString() }
        );

        CapturingCompile compiler = new CapturingCompile();
        compiler.setOptions(options);
        int result = compiler.run_compilation(
            options.inputFile.getPath(),
            options.outputFile.getPath()
        );

        assertEquals(
            0,
            result,
            () -> "SCORE7 SLEIGH compile failed:\n" + String.join("\n", compiler.diagnostics)
        );
        assertEquals(
            0,
            compiler.numErrors(),
            () -> "SCORE7 SLEIGH errors:\n" + String.join("\n", compiler.diagnostics)
        );
        assertTrue(Files.size(output) > 0, "SCORE7.sla must be non-empty");
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
