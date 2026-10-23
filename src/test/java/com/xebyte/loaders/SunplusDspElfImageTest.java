package com.xebyte.loaders;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.opinion.LoadSpec;
import junit.framework.TestCase;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Container and address-unit tests, not target DSP execution proof. */
public class SunplusDspElfImageTest extends TestCase {
    private byte[] fixture(ByteOrder order) {
        byte[] out = new byte[256];
        byte[] names = "\0int_pm\0int_dm\0.shstrtab\0".getBytes(StandardCharsets.US_ASCII);
        ByteBuffer b = ByteBuffer.wrap(out).order(order);
        b.put(new byte[] {0x7f, 'E', 'L', 'F', 1, (byte)(order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1});
        b.putShort(16, (short)2).putShort(18, (short)0x6423).putInt(20, 1);
        b.putInt(24, 0x1800).putInt(32, 96).putShort(40, (short)52);
        b.putShort(46, (short)40).putShort(48, (short)4).putShort(50, (short)3);
        System.arraycopy(names, 0, out, 64, names.length);
        out[52] = 0x0a; out[53] = 0; out[54] = 0x0f;
        out[55] = 0x12; out[56] = 0x34;
        int base = 136;
        b.putInt(base, 1).putInt(base + 4, 1).putInt(base + 8, 6).putInt(base + 12, 0x1800);
        b.putInt(base + 16, 52).putInt(base + 20, 3).putInt(base + 32, 3);
        base = 176;
        b.putInt(base, 8).putInt(base + 4, 1).putInt(base + 8, 3).putInt(base + 12, 0x100);
        b.putInt(base + 16, 55).putInt(base + 20, 2).putInt(base + 32, 2);
        base = 216;
        b.putInt(base, 15).putInt(base + 4, 3).putInt(base + 16, 64).putInt(base + 20, names.length);
        return out;
    }

    private void fails(byte[] bytes) {
        try { SunplusDspElfImage.parse(bytes); fail("Invalid image accepted"); }
        catch (IOException expected) { assertNotNull(expected.getMessage()); }
    }

    public void testBothElfByteOrdersPreservePmPayloadByteOrder() throws Exception {
        for (ByteOrder order : new ByteOrder[] {ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN}) {
            var result = SunplusDspElfImage.parse(fixture(order));
            assertEquals(2, result.segments().size());
            var pm = result.segments().get(0);
            var dm = result.segments().get(1);
            assertEquals(0x1800L, pm.wordAddress());
            assertEquals(0x4800L, pm.byteAddress());
            assertEquals(0x200L, dm.byteAddress());
            assertTrue(Arrays.equals(new byte[] {0x0a, 0, 0x0f}, pm.bytes()));
            assertTrue(Arrays.equals(new byte[] {0x12, 0x34}, dm.bytes()));
        }
    }
    public void testRejectsRawObjectsAndDifferentMachine() {
        byte[] f = fixture(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer.wrap(f).order(ByteOrder.LITTLE_ENDIAN).putShort(16, (short)1); fails(f);
        f = fixture(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer.wrap(f).order(ByteOrder.LITTLE_ENDIAN).putShort(18, (short)8); fails(f);
    }
    public void testRejectsPartialWords() {
        byte[] f = fixture(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer.wrap(f).order(ByteOrder.LITTLE_ENDIAN).putInt(156, 2); fails(f);
    }
    public void testRejectsOutOfRangeAddress() {
        byte[] f = fixture(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer.wrap(f).order(ByteOrder.LITTLE_ENDIAN).putInt(148, 0x4000); fails(f);
    }
    public void testRejectsOutOfRangeDirectoryAndPayload() {
        byte[] f = fixture(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer.wrap(f).order(ByteOrder.LITTLE_ENDIAN).putInt(32, 0x7fffffff); fails(f);
        f = fixture(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer.wrap(f).order(ByteOrder.LITTLE_ENDIAN).putInt(152, 255); fails(f);
    }
    public void testRejectsUnknownOrDuplicateSection() {
        byte[] f = fixture(ByteOrder.LITTLE_ENDIAN); f[65] = 'X'; fails(f);
        f = fixture(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer.wrap(f).order(ByteOrder.LITTLE_ENDIAN).putInt(176, 1).putInt(196, 3); fails(f);
    }
    public void testRejectsMissingPmAndRelocations() {
        byte[] f = fixture(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer.wrap(f).order(ByteOrder.LITTLE_ENDIAN).putInt(144, 0); fails(f);
        f = fixture(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer.wrap(f).order(ByteOrder.LITTLE_ENDIAN).putInt(180, 9); fails(f);
    }
    public void testInputAndReturnedPayloadAreNotMutableAliases() throws Exception {
        byte[] file = fixture(ByteOrder.LITTLE_ENDIAN);
        var parsed = SunplusDspElfImage.parse(file); file[52] = 0;
        byte[] first = parsed.segments().get(0).bytes(); first[0] = 1;
        assertEquals(0x0a, parsed.segments().get(0).bytes()[0]);
    }
    public void testLoaderSelectsWordAddressedSunplusOnly() throws Exception {
        var loader = new SunplusDspElfLoader();
        var specs = loader.findSupportedLoadSpecs(new ByteArrayProvider(fixture(ByteOrder.LITTLE_ENDIAN)));
        assertEquals(1, specs.size());
        LoadSpec spec = specs.iterator().next();
        assertEquals(SunplusDspElfLoader.LANGUAGE, spec.getLanguageCompilerSpec().languageID.toString());
        assertEquals(0x4800L, spec.getDesiredImageBase());
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider(new byte[64])).isEmpty());
    }
    public void testActualSdkImageWhenSupplied() throws Exception {
        String path = System.getProperty("sunplus.sdk.fixture");
        if (path == null) return; // Separate run report records whether this gate was enabled.
        var parsed = SunplusDspElfImage.parse(Files.readAllBytes(Path.of(path)));
        assertEquals(0x1800L, parsed.entryWord());
        assertEquals(2, parsed.segments().size());
        assertEquals(11L, parsed.segments().get(0).wordCount());
        assertEquals(0x1800L, parsed.segments().get(0).wordAddress());
        assertEquals(0x100L, parsed.segments().get(1).wordAddress());
        assertTrue(parsed.symbols().stream().anyMatch(s -> s.name().equals("sdk_probe") && s.wordAddress() == 0x1800));
    }
}
