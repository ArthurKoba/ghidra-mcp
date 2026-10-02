// Runtime decode acceptance for SunplusSPHEAudioDSP.
// The imported fixture contains, in order:
//   0x19820F -> JUMP $1820
//   0x0A000F -> RTS
//   0x80023A -> AR = DM($0023)
//   0x80021A -> AR = DM($0021)
//   0x0A001F -> RTI
//   0x180250 -> IF EQ JUMP $0025
//   0x22E21F -> AR = AR - 1
//   0x0F02F6 -> SR = LSHIFT AR BY -10 (HI)
//   0x0D00AF -> AR = SR1
//   0x18036F -> JUMP $0036 (must stay generic outside srvdsp context)
//   0x040040 -> DIS_INTS
//   0x040060 -> ENA_INTS
//   0x0A0000 -> IF EQ RTS
//   0x0A0005 -> IF GE RTS
//   0x26EA0F -> AF = AR - AY1
//   0x226A04 -> IF LT AR = AR + AY1
//   0x181445 -> IF GE JUMP $0144
//   0x1C0E20 -> IF EQ CALL $00E2
//   0x050000 -> SAT_MR
//   0x028000 -> IDLE
//   0x0F27F8 -> SR = ASHIFT SR1 BY -8 (HI)
//   0x0F30F8 -> SR = ASHIFT SI BY -8 (LO)
//   0x2AE0AA -> NONE = AX0 - AY0
//   0x2A6041 -> AR = AX0 + AY0, AY0 = AX1
//   0x2EE2CA -> AF = AR - AY0, MR1 = AR
//   0x5000A0 -> AR = PM(I0,M0)
//   0x5800C0 -> PM(I0,M0) = MR1
//   0x0C3000 -> ENA_M_MODE
//   0x0CC000 -> ENA_TIMER
//   0x090010 -> MODIFY(I4,M4)
//   0x04001F -> POP STS, POP CNTR, POP PC, POP LOOP
//   0x101242 -> SR = LSHIFT AR (LO), AY0 = MX0
//   0x0E1A0F -> SR = SR OR LSHIFT AR (LO)
//   0x73081D -> AR = AY1 - 1, AX1 = DM(I7,M5)
//   0x62620E -> AR = AR + AY0, AX0 = DM(I3,M2)
//   0x21180F -> MR = MR + MX0 * 0 (SS)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class SunplusDSPDecodeSmoke extends GhidraScript {
    private Instruction decode(long wordAddress) throws Exception {
        var pm = currentProgram.getAddressFactory().getAddressSpace("PM");
        Address address = pm.getAddress(wordAddress * pm.getAddressableUnitSize());
        if (!disassemble(address)) {
            throw new AssertionError("Disassembly failed at " + address);
        }
        Instruction instruction = currentProgram.getListing().getInstructionAt(address);
        if (instruction == null) {
            throw new AssertionError("No instruction created at " + address);
        }
        println(address + " " + instruction);
        return instruction;
    }

    private void requireMnemonic(Instruction instruction, String expected) {
        String actual = instruction.getMnemonicString();
        if (!expected.equals(actual)) {
            throw new AssertionError(
                "Expected " + expected + " at " + instruction.getAddress() +
                ", got " + actual + " (" + instruction + ")");
        }
    }

    private void requireText(Instruction instruction, String expectedFragment) {
        String actual = instruction.toString();
        String normalizedActual = actual.replaceAll("\\s+", "");
        String normalizedExpected = expectedFragment.replaceAll("\\s+", "");
        if (!normalizedActual.contains(normalizedExpected)) {
            throw new AssertionError(
                "Expected text containing '" + expectedFragment + "' at " +
                instruction.getAddress() + ", got: " + actual);
        }
    }

    private void requireDmRead(Instruction instruction, long expectedAddress) {
        requireMnemonic(instruction, "DMREAD");
        String text = instruction.toString();
        if (!text.contains("AR")) {
            throw new AssertionError("Expected AR destination, got: " + text);
        }
        Scalar scalar = instruction.getScalar(1);
        if (scalar == null || scalar.getUnsignedValue() != expectedAddress) {
            throw new AssertionError(
                "Expected DM address 0x" + Long.toHexString(expectedAddress) +
                ", got: " + text);
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new AssertionError("No current program");
        }
        if (!"SunplusSPHEAudioDSP:BE:16:default".equals(
                currentProgram.getLanguageID().getIdAsString())) {
            throw new AssertionError("Unexpected language: " + currentProgram.getLanguageID());
        }

        Instruction jump = decode(0);
        requireMnemonic(jump, "JUMP");
        Address[] flows = jump.getFlows();
        long unitSize = flows.length == 0 ? 1 : flows[0].getAddressSpace().getAddressableUnitSize();
        long targetWordAddress = flows.length == 0 ? -1 : flows[0].getOffset() / unitSize;
        if (flows.length != 1 || targetWordAddress != 0x1820L) {
            throw new AssertionError("Expected JUMP target PM:1820, got: " + jump +
                " rawFlow=" + (flows.length == 0 ? "<none>" : flows[0]));
        }

        requireMnemonic(decode(1), "RTS");
        requireDmRead(decode(2), 0x23L);
        requireDmRead(decode(3), 0x21L);
        requireMnemonic(decode(4), "RTI");
        requireText(decode(5), "IF EQ JUMP");
        requireText(decode(6), "AR - 1");
        requireText(decode(7), "LSHIFT AR BY");
        requireText(decode(8), "AR = SR1");

        Instruction genericResidentCollision = decode(9);
        requireMnemonic(genericResidentCollision, "JUMP");
        Address[] genericFlows = genericResidentCollision.getFlows();
        long genericUnitSize = genericFlows.length == 0 ? 1 :
            genericFlows[0].getAddressSpace().getAddressableUnitSize();
        long genericTarget = genericFlows.length == 0 ? -1 :
            genericFlows[0].getOffset() / genericUnitSize;
        if (genericFlows.length != 1 || genericTarget != 0x36L) {
            throw new AssertionError(
                "Expected generic local JUMP target PM:0036, got: " + genericResidentCollision);
        }

        requireMnemonic(decode(10), "DIS_INTS");
        requireMnemonic(decode(11), "ENA_INTS");
        requireText(decode(12), "IF EQ RTS");
        requireText(decode(13), "IF GE RTS");
        requireText(decode(14), "AF = AR - AY1");
        requireText(decode(15), "IF LT AR = AR + AY1");
        requireText(decode(16), "IF GE JUMP");
        requireText(decode(17), "IF EQ CALL");
        requireMnemonic(decode(18), "SAT_MR");
        requireMnemonic(decode(19), "IDLE");
        requireText(decode(20), "ASHIFT SR1 BY");
        requireText(decode(21), "ASHIFT SI BY");
        requireText(decode(22), "NONE = AX0 - AY0");
        requireText(decode(23), "AR = AX0 + AY0");
        requireText(decode(23), "AY0 = AX1");
        requireText(decode(24), "AF = AR - AY0");
        requireText(decode(24), "MR1 = AR");
        requireText(decode(25), "AR = PM(");
        requireText(decode(25), "I4");
        requireText(decode(26), "PM(");
        requireText(decode(26), "MR1");
        requireMnemonic(decode(27), "ENA_M_MODE");
        requireMnemonic(decode(28), "ENA_TIMER");
        requireText(decode(29), "MODIFY(");
        requireText(decode(29), "I4");
        requireText(decode(29), "M4");
        requireText(decode(30), "POP STS");
        requireText(decode(30), "POP LOOP");
        requireText(decode(31), "LSHIFT AR");
        requireText(decode(31), "AY0 = MX0");
        requireText(decode(32), "SR OR LSHIFT AR");
        requireText(decode(33), "AY1 - 1");
        requireText(decode(33), "AX1 = DM(");
        requireText(decode(33), "I7");
        requireText(decode(33), "M5");
        requireText(decode(34), "AR = AR + AY0");
        requireText(decode(34), "AX0 = DM(");
        requireText(decode(34), "I3");
        requireText(decode(34), "M2");
        requireText(decode(35), "MR = MR + MX0 * 0 (SS)");

        println("SUNPLUS_DSP_DECODE_SMOKE=PASS");
    }
}
