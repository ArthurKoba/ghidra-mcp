// SCORE7 external disassembly bridge for Ghidra.
// Uses GNU binutils' maintained Sunplus S+CORE backend without changing the
// program language or creating Ghidra Instruction objects.
//
// Usage examples:
//   start=0x0 length=0x1000 endian=le
//   start=0x20000 length=all endian=le max_lines=4000
//
// @category Analysis.SCORE7

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class Score7ExternalDisassemble extends GhidraScript {

    private static final String OBJDUMP = "/usr/local/bin/score-elf-objdump";
    private static final long MAX_BYTES = 16L * 1024L * 1024L;

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("No current program is open");
        }
        if (!Files.isExecutable(Paths.get(OBJDUMP))) {
            throw new IllegalStateException(
                "SCORE7 disassembler is not installed: " + OBJDUMP
            );
        }

        Map<String, String> options = parseOptions(getScriptArgs());
        Address start = parseStart(options.get("start"));
        long available = currentProgram.getMaxAddress().subtract(start) + 1;
        long length = parseLength(options.get("length"), available);
        String endian = options.getOrDefault("endian", "le").toLowerCase(Locale.ROOT);
        int maxLines = parseInt(options.getOrDefault("max_lines", "2000"), "max_lines");

        if (!endian.equals("le") && !endian.equals("be")) {
            throw new IllegalArgumentException("endian must be le or be");
        }
        if (maxLines < 1 || maxLines > 20000) {
            throw new IllegalArgumentException("max_lines must be between 1 and 20000");
        }
        if (length < 1 || length > MAX_BYTES) {
            throw new IllegalArgumentException(
                "length must be between 1 and " + MAX_BYTES + " bytes"
            );
        }
        if (length > available) {
            length = available;
        }

        println("SCORE7_EXTERNAL_DISASSEMBLY");
        println("program=" + currentProgram.getName());
        println("start=" + start);
        println("length=" + length);
        println("endian=" + endian);

        byte[] bytes = new byte[(int) length];
        Memory memory = currentProgram.getMemory();
        int read = memory.getBytes(start, bytes);
        if (read <= 0) {
            throw new IllegalStateException("No readable bytes at " + start);
        }

        Path input = Files.createTempFile("ghidra-score7-", ".bin");
        Path exportDir = Paths.get("/artifacts/exports");
        Files.createDirectories(exportDir);
        String safeName = currentProgram.getName().replaceAll("[^A-Za-z0-9._-]+", "_");
        Path output = exportDir.resolve(
            safeName + "-score7-" + Long.toHexString(start.getOffset()) +
            "-" + Integer.toHexString(read) + "-" + endian + ".asm"
        );

        try {
            Files.write(input, read == bytes.length ? bytes : java.util.Arrays.copyOf(bytes, read));

            ProcessBuilder pb = new ProcessBuilder(
                OBJDUMP,
                "-D",
                "-b", "binary",
                "-m", "score7",
                endian.equals("le") ? "-EL" : "-EB",
                "--adjust-vma=0x" + Long.toHexString(start.getOffset()),
                input.toString()
            );
            pb.redirectErrorStream(true);

            Process process = pb.start();
            int totalLines = 0;
            try (
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
                );
                BufferedWriter writer = Files.newBufferedWriter(output)
            ) {
                String line;
                while ((line = reader.readLine()) != null) {
                    writer.write(line);
                    writer.newLine();
                    if (totalLines < maxLines) {
                        println(line);
                    }
                    totalLines++;
                }
            }

            int exit = process.waitFor();
            println("score7_objdump_exit=" + exit);
            println("lines=" + totalLines);
            println("full_output=" + output);

            if (totalLines > maxLines) {
                println(
                    "preview_truncated=true shown_lines=" + maxLines +
                    " total_lines=" + totalLines
                );
            }

            if (exit != 0) {
                throw new IllegalStateException(
                    "score-elf-objdump failed with exit code " + exit
                );
            }
        }
        finally {
            Files.deleteIfExists(input);
        }
    }

    private Map<String, String> parseOptions(String[] args) {
        Map<String, String> result = new HashMap<>();
        for (String arg : args) {
            if (arg == null || arg.isBlank()) {
                continue;
            }
            int equals = arg.indexOf('=');
            if (equals <= 0 || equals == arg.length() - 1) {
                throw new IllegalArgumentException(
                    "Arguments must use key=value syntax: " + arg
                );
            }
            result.put(
                arg.substring(0, equals).trim().toLowerCase(Locale.ROOT),
                arg.substring(equals + 1).trim()
            );
        }
        return result;
    }

    private Address parseStart(String raw) {
        if (raw == null || raw.isBlank()) {
            return currentProgram.getMinAddress();
        }

        Address direct = currentProgram.getAddressFactory().getAddress(raw);
        if (direct != null) {
            return direct;
        }

        long offset = decodeLong(raw, "start");
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        return space.getAddress(offset);
    }

    private long parseLength(String raw, long available) {
        if (raw == null || raw.isBlank()) {
            return Math.min(0x1000L, available);
        }
        if (raw.equalsIgnoreCase("all")) {
            return Math.min(available, MAX_BYTES);
        }
        return decodeLong(raw, "length");
    }

    private long decodeLong(String value, String name) {
        try {
            String clean = value.trim().toLowerCase(Locale.ROOT);
            if (clean.startsWith("0x")) {
                return Long.parseUnsignedLong(clean.substring(2), 16);
            }
            return Long.parseLong(clean);
        }
        catch (NumberFormatException exc) {
            throw new IllegalArgumentException(
                name + " must be decimal or 0x-prefixed hexadecimal"
            );
        }
    }

    private int parseInt(String value, String name) {
        long parsed = decodeLong(value, name);
        if (parsed > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(name + " is too large");
        }
        return (int) parsed;
    }
}
