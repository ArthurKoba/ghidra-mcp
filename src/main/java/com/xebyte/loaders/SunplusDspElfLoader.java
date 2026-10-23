package com.xebyte.loaders;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.List;

/** Ghidra importer for the SDK's explicitly linked PM24/DM16 ELF images.
 * Never treats MIPS ELF or arbitrary .bin data as this format. */
public class SunplusDspElfLoader extends AbstractLibrarySupportLoader {
    public static final String LANGUAGE = "SunplusSPHEAudioDSP:BE:16:default";

    @Override public String getName() { return "Sunplus DSP SDK ELF (PM24/DM16)"; }
    @Override public LoaderTier getTier() { return LoaderTier.SPECIALIZED_TARGET_LOADER; }
    @Override public int getTierPriority() { return 50; }

    private SunplusDspElfImage image(ByteProvider provider) throws IOException {
        long size = provider.length();
        if (size < 52 || size > SunplusDspElfImage.MAX_BYTES) throw new IOException("SDK image size out of bounds");
        return SunplusDspElfImage.parse(provider.readBytes(0, size));
    }

    @Override public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        final SunplusDspElfImage parsed;
        try { parsed = image(provider); }
        catch (IOException invalid) { return List.of(); }
        long base = parsed.segments().stream().filter(s -> s.space().equals("PM"))
            .findFirst().orElseThrow().byteAddress();
        return List.of(new LoadSpec(this, base, new LanguageCompilerSpecPair(LANGUAGE, "default"), true));
    }

    @Override protected void load(Program program, ImporterSettings settings) throws IOException, CancelledException {
        SunplusDspElfImage parsed = image(settings.provider());
        if (!program.getLanguageID().toString().equals(LANGUAGE)) throw new IOException("Wrong target DSP language");
        for (SunplusDspElfImage.Segment segment : parsed.segments()) {
            settings.monitor().checkCancelled();
            AddressSpace space = program.getAddressFactory().getAddressSpace(segment.space());
            if (space == null || space.getAddressableUnitSize() != segment.wordBytes()) {
                throw new IOException("Language address unit mismatch for " + segment.space());
            }
            Address start = space.getAddress(segment.byteAddress());
            if (start.getAddressableWordOffset() != segment.wordAddress()) throw new IOException("Word/byte conversion failed");
            try {
                MemoryBlock block = program.getMemory().createInitializedBlock(segment.name(), start,
                    new ByteArrayInputStream(segment.bytes()), segment.bytes().length, settings.monitor(), false);
                block.setRead(true);
                // Both SDK linker regions are RAM. PM holds writable tables
                // as well as instructions; read-only PM would be a false fact.
                block.setWrite(true);
                block.setExecute(segment.space().equals("PM"));
                block.setComment("SDK linker section; target RAM/MMIO ownership and hardware execution not inferred.");
            } catch (CancelledException cancelled) { throw cancelled; }
            catch (Exception failed) { throw new IOException("Cannot map SDK section " + segment.name(), failed); }
        }
        for (SunplusDspElfImage.Symbol symbol : parsed.symbols()) {
            settings.monitor().checkCancelled();
            AddressSpace space = program.getAddressFactory().getAddressSpace(symbol.space());
            Address address = space.getAddress(symbol.wordAddress() * space.getAddressableUnitSize());
            try {
                program.getSymbolTable().createLabel(address, symbol.name(), SourceType.IMPORTED);
                if (symbol.function()) program.getSymbolTable().addExternalEntryPoint(address);
            } catch (Exception invalidName) {
                settings.log().appendMsg("SDK symbol not imported: " + symbol.name() + ": " + invalidName.getMessage());
            }
        }
        // Honor only an explicit in-range ELF entry. Do not create functions
        // from arbitrary data or from all global labels.
        for (SunplusDspElfImage.Segment segment : parsed.segments()) {
            if (segment.space().equals("PM") && parsed.entryWord() >= segment.wordAddress() &&
                parsed.entryWord() < segment.wordAddress() + segment.wordCount()) {
                program.getSymbolTable().addExternalEntryPoint(program.getAddressFactory().getAddressSpace("PM")
                    .getAddress(parsed.entryWord() * 3));
            }
        }
    }
}
