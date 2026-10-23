package com.xebyte.loaders;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Strict container reader for the SDK's linked Open21xx PM24/DM16 images.
 * This parses ELF metadata only; it does not decode DSP instructions. */
public record SunplusDspElfImage(long entryWord, List<Segment> segments, List<Symbol> symbols) {
    public static final int MAX_BYTES = 4 * 1024 * 1024;

    public record Segment(String name, String space, long wordAddress, int wordBytes, byte[] bytes) {
        public Segment { bytes = bytes.clone(); }
        @Override public byte[] bytes() { return bytes.clone(); }
        public long byteAddress() { return wordAddress * wordBytes; }
        public long wordCount() { return bytes.length / wordBytes; }
    }
    public record Symbol(String name, String space, long wordAddress, boolean function) {}
    private record Section(int name, int type, long flags, long address, int offset, int size,
                           int link, int info, int alignment, int entrySize) {}

    public SunplusDspElfImage {
        segments = List.copyOf(segments);
        symbols = List.copyOf(symbols);
    }

    public static SunplusDspElfImage parse(byte[] file) throws IOException {
        if (file.length < 52 || file.length > MAX_BYTES || file[0] != 0x7f ||
            file[1] != 'E' || file[2] != 'L' || file[3] != 'F' || file[4] != 1 ||
            (file[5] != 1 && file[5] != 2) || file[6] != 1) {
            throw new IOException("Not a bounded ELF32 image");
        }
        ByteBuffer data = ByteBuffer.wrap(file).order(file[5] == 1 ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        if (Short.toUnsignedInt(data.getShort(16)) != 2 ||
            Short.toUnsignedInt(data.getShort(18)) != 0x6423 || data.getInt(20) != 1) {
            throw new IOException("Requires linked ET_EXEC / EM_ADSP218X");
        }
        long entry = Integer.toUnsignedLong(data.getInt(24));
        long tableOffset = Integer.toUnsignedLong(data.getInt(32));
        int width = Short.toUnsignedInt(data.getShort(46));
        int count = Short.toUnsignedInt(data.getShort(48));
        int namesIndex = Short.toUnsignedInt(data.getShort(50));
        if (width < 40 || count == 0 || count > 4096 || namesIndex >= count ||
            tableOffset < 52 || tableOffset + (long) count * width > file.length) {
            throw new IOException("Invalid ELF section directory");
        }
        List<Section> sections = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            int base = (int) tableOffset + i * width;
            Section section = new Section(data.getInt(base), data.getInt(base + 4),
                Integer.toUnsignedLong(data.getInt(base + 8)), Integer.toUnsignedLong(data.getInt(base + 12)),
                data.getInt(base + 16), data.getInt(base + 20), data.getInt(base + 24),
                data.getInt(base + 28), data.getInt(base + 32), data.getInt(base + 36));
            if (section.size < 0 || section.offset < 0 ||
                (section.type != 8 && (long) section.offset + section.size > file.length)) {
                throw new IOException("ELF section outside file");
            }
            if ((section.type == 4 || section.type == 9) && section.size != 0) {
                throw new IOException("Unapplied ELF relocations");
            }
            sections.add(section);
        }
        Section names = sections.get(namesIndex);
        if (names.type != 3) throw new IOException("Missing section-name string table");
        List<Segment> segments = new ArrayList<>();
        List<Symbol> symbols = new ArrayList<>();
        Set<String> spaces = new HashSet<>();
        for (Section section : sections) {
            if (section.type == 0 || (section.flags & 2) == 0 || section.size == 0) continue;
            String name = string(file, names, section.name);
            String space;
            int unit;
            if (name.equals("int_pm")) { space = "PM"; unit = 3; }
            else if (name.equals("int_dm")) { space = "DM"; unit = 2; }
            else throw new IOException("Unsupported allocated section: " + name);
            if (section.type != 1 || section.size % unit != 0 ||
                section.address + section.size / unit > 0x4000 || !spaces.add(space)) {
                throw new IOException("Invalid, duplicate, or out-of-range " + space + " segment");
            }
            segments.add(new Segment(name, space, section.address, unit,
                Arrays.copyOfRange(file, section.offset, section.offset + section.size)));
        }
        if (!spaces.contains("PM")) throw new IOException("Missing initialized PM");
        for (Section section : sections) {
            if (section.type != 2) continue;
            if (section.entrySize != 16 || section.size % 16 != 0 ||
                section.link < 0 || section.link >= count || sections.get(section.link).type != 3) {
                throw new IOException("Invalid ELF symbol table");
            }
            Section strings = sections.get(section.link);
            for (int at = section.offset; at < section.offset + section.size; at += 16) {
                int nameOffset = data.getInt(at);
                long value = Integer.toUnsignedLong(data.getInt(at + 4));
                int info = Byte.toUnsignedInt(file[at + 12]);
                int index = Short.toUnsignedInt(data.getShort(at + 14));
                if (index == 0 && (info >> 4) == 1 && nameOffset != 0) {
                    throw new IOException("Undefined global ELF symbol");
                }
                if (nameOffset == 0 || index == 0 || index >= count || (info & 15) == 3) continue;
                String sectionName = string(file, names, sections.get(index).name);
                for (Segment segment : segments) {
                    if (sectionName.equals(segment.name) && value >= segment.wordAddress &&
                        value < segment.wordAddress + segment.wordCount()) {
                        symbols.add(new Symbol(string(file, strings, nameOffset), segment.space,
                            value, (info & 15) == 2));
                    }
                }
            }
        }
        return new SunplusDspElfImage(entry, segments, symbols);
    }

    private static String string(byte[] file, Section strings, int offset) throws IOException {
        if (offset < 0 || offset >= strings.size) throw new IOException("Invalid ELF string offset");
        int at = strings.offset + offset;
        int end = at;
        while (end < strings.offset + strings.size && file[end] != 0) {
            if (Byte.toUnsignedInt(file[end]) > 127) throw new IOException("Non-ASCII ELF symbol");
            end++;
        }
        if (end == strings.offset + strings.size) throw new IOException("Unterminated ELF string");
        return new String(file, at, end - at, StandardCharsets.US_ASCII);
    }
}
