package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.Map;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * Regression coverage for the get_xrefs_to / get_xrefs_from resolution-feedback fix: a
 * wrong-but-parseable address and a genuine zero-reference address used to be
 * indistinguishable - both returned count=0 with nothing else to tell them apart. The
 * response now always names the memory block the queried address resolved into, so
 * "count=0, block=null" (nothing backs this address at all) reads differently from
 * "count=0, block=.text" (a real location, genuinely no references).
 */
public class XrefCallGraphServiceResolutionGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder("xref-resolution", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x1100);

        // A real reference: 0x1000 -> 0x1004.
        builder.withTransaction(() -> program.getReferenceManager().addMemoryReference(
            builder.addr("0x1000"), builder.addr("0x1004"),
            RefType.DATA, SourceType.USER_DEFINED, 0));
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> body(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Ok);
        Object data = ((Response.Ok) response).data();
        assertTrue("expected the response to be a map", data instanceof Map);
        return (Map<String, Object>) data;
    }

    private XrefCallGraphService service() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        return new XrefCallGraphService(provider, new DirectThreadingStrategy());
    }

    @Test
    public void xrefsToRealReferenceReportsItsBlock() {
        Map<String, Object> b = body(service().getXrefsTo("0x1004", 0, 100, ""));
        assertEquals(1, b.get("count"));
        assertEquals("0x1004", b.get("resolved_address"));
        assertEquals(".text", b.get("block"));
    }

    @Test
    public void xrefsToRealLocationWithNoReferencesStaysDistinctFromUnbackedAddress() {
        // Inside the mapped block, genuinely zero references - a real negative.
        Map<String, Object> zeroButReal = body(service().getXrefsTo("0x1050", 0, 100, ""));
        assertEquals(0, zeroButReal.get("count"));
        assertEquals("a real address's block must be reported even with zero references - "
                + "this is what a genuine negative looks like",
            ".text", zeroButReal.get("block"));

        // Not inside any memory block at all - the exact case this fix exists to surface.
        // Same count=0 as above, but block is null, which is the only thing that tells them
        // apart. Before this fix neither response carried any resolution info at all.
        Map<String, Object> unbacked = body(service().getXrefsTo("0x50000", 0, 100, ""));
        assertEquals(0, unbacked.get("count"));
        assertNull("an address with no covering memory block must report block=null, "
                + "distinguishing it from a real address that just has no references",
            unbacked.get("block"));
    }

    @Test
    public void xrefsFromAlsoReportsResolution() {
        Map<String, Object> b = body(service().getXrefsFrom("0x1000", 0, 100, ""));
        assertEquals(1, b.get("count"));
        assertEquals("0x1000", b.get("resolved_address"));
        assertEquals(".text", b.get("block"));

        Map<String, Object> unbacked = body(service().getXrefsFrom("0x50000", 0, 100, ""));
        assertEquals(0, unbacked.get("count"));
        assertNull(unbacked.get("block"));
    }
}
