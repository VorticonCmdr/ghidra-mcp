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
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * Regression coverage for /get_bulk_xrefs: an unresolvable address string used to produce the
 * exact same result (a bare empty array) as a resolvable address with zero real references,
 * making a caller mistake indistinguishable from a genuine negative. Each address now maps to
 * an object carrying either its references or the reason it didn't resolve.
 */
public class XrefCallGraphServiceBulkXrefsGhidraTest {

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
        builder = new ProgramBuilder("bulk-xrefs", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x1100);

        // A real reference: 0x1000 -> 0x1004, so get_bulk_xrefs("0x1004") has something to find.
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
    private static Map<String, Object> resultMap(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Ok);
        Object data = ((Response.Ok) response).data();
        assertTrue("expected the top-level response to be a map", data instanceof Map);
        return (Map<String, Object>) data;
    }

    @Test
    public void resolvedAddressWithRealReferencesReportsThem() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        XrefCallGraphService service = new XrefCallGraphService(provider, new DirectThreadingStrategy());

        Response response = service.getBulkXrefs(List.of("0x1004"));
        Map<String, Object> result = resultMap(response);

        assertTrue(result.containsKey("0x1004"));
        @SuppressWarnings("unchecked")
        Map<String, Object> entry = (Map<String, Object>) result.get("0x1004");
        assertFalse("a resolved address with a real reference must not carry an error",
            entry.containsKey("error"));
        assertEquals(1, entry.get("count"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> refs = (List<Map<String, Object>>) entry.get("references");
        assertEquals(1, refs.size());
    }

    @Test
    public void unresolvableAddressStringReportsAnErrorNotAnEmptyArray() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        XrefCallGraphService service = new XrefCallGraphService(provider, new DirectThreadingStrategy());

        Response response = service.getBulkXrefs(List.of("not-an-address"));
        Map<String, Object> result = resultMap(response);

        assertTrue(result.containsKey("not-an-address"));
        @SuppressWarnings("unchecked")
        Map<String, Object> entry = (Map<String, Object>) result.get("not-an-address");
        assertTrue("an unresolvable address string must carry an 'error' key - "
                + "this is the exact regression being guarded against: before the fix, this "
                + "entry was a bare empty array indistinguishable from a resolved address with "
                + "zero real references",
            entry.containsKey("error"));
        assertFalse("an unresolved address must not report a references list",
            entry.containsKey("references"));
    }

    @Test
    public void resolvedAddressWithNoReferencesIsDistinctFromAnUnresolvedOne() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        XrefCallGraphService service = new XrefCallGraphService(provider, new DirectThreadingStrategy());

        // 0x1050 is inside the mapped .text block but has no reference to it - a genuine
        // negative, which must still come back with count=0 and no error, not conflated with
        // the unresolvable-string case above.
        Response response = service.getBulkXrefs(List.of("0x1050"));
        Map<String, Object> result = resultMap(response);

        @SuppressWarnings("unchecked")
        Map<String, Object> entry = (Map<String, Object>) result.get("0x1050");
        assertFalse("a resolved address with zero references must not carry an error",
            entry.containsKey("error"));
        assertEquals(0, entry.get("count"));
    }
}
