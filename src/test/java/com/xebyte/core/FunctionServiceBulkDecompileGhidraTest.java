package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/** Bulk function reads retain typed errors and report all requested entries, including truncation. */
public class FunctionServiceBulkDecompileGhidraTest {

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
        builder = new ProgramBuilder("bulk-decompile", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x1100);
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

    private FunctionBundleService service() {
        ProgramProvider provider = new ProgramProvider() {
            @Override public Program getCurrentProgram() { return program; }
            @Override public Program getProgram(String name) { return program; }
            @Override public Program[] getAllOpenPrograms() { return new Program[] {program}; }
            @Override public void setCurrentProgram(Program p) { }
        };
        return new FunctionBundleService(provider, new DirectThreadingStrategy(),
            new FunctionService(provider, new DirectThreadingStrategy()));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void unresolvedFunctionReportsAnErrorRowNotAnErrorString() {
        Map<String, Object> b = body(service().getFunctions("", "does_not_exist", "signature", false, 6, 3, false, "", ""));

        assertEquals(0, b.get("count"));
        assertEquals(1, b.get("requested"));
        assertEquals(1, b.get("total"));
        assertEquals(false, b.get("truncated"));
        assertFalse("no truncation happened - there must be no truncation_note",
            b.containsKey("truncation_note"));

        Map<String, Object> results = (Map<String, Object>) b.get("functions");
        assertEquals(1, results.size());
        Map<String, Object> row = (Map<String, Object>) results.get("does_not_exist");
        assertTrue("error row must carry an 'error' key, not a bare 'Error: ...' string value "
                + "under a generic key - this is the exact regression being guarded against",
            row.get("error") instanceof String);
        assertFalse("an error row must not carry a 'decompiled' key",
            row.containsKey("decompiled"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void requestingMoreThanTheCapTruncatesHonestlyInsteadOfSilently() {
        // 25 unresolvable refs. MAX_FUNCTIONS=20, so this must stop at 20 rows and say so -
        // not silently return however many it felt like, the exact regression this fix closes.
        StringBuilder refs = new StringBuilder();
        for (int i = 0; i < 25; i++) {
            if (i > 0) refs.append(",");
            refs.append("nonexistent_").append(i);
        }

        Map<String, Object> b = body(service().getFunctions("", refs.toString(), "signature", false, 6, 3, false, "", ""));

        assertEquals("total must reflect everything requested, even the part dropped",
            25, b.get("total"));
        assertEquals("results must stop at MAX_FUNCTIONS, not silently continue or silently "
                + "stop short", 20, b.get("requested"));
        assertEquals(0, b.get("count"));
        assertEquals(true, b.get("truncated"));
        assertTrue("a truncated batch must explain itself", b.containsKey("truncation_note"));

        Map<String, Object> results = (Map<String, Object>) b.get("functions");
        assertEquals(20, results.size());
    }

    @Test
    public void emptyFunctionsParameterIsRejectedUpFront() {
        Response r = service().getFunctions("", "", "signature", false, 6, 3, false, "", "");
        assertTrue(r.toJson(), r instanceof Response.Err);
    }
}
