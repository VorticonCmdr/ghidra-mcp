package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
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
 * Regression coverage for decompile_function's bulk mode (functions=...), scoped to the two
 * defects actually fixed: silent truncation past MAX_FUNCTIONS, and per-function failures
 * reported as ordinary string values ("Error: ...") indistinguishable from real decompiled
 * code. Deliberately does not exercise a successful decompile - that path reuses the same
 * {name, address, decompiled} fields single-mode decompileFunctionByAddress already emits
 * unchanged, and this repo has no existing test that invokes the real decompiler backend to
 * build on; these assertions target the envelope logic itself (which needs no decompile to
 * reach), not decompiler correctness.
 */
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

    private FunctionService service() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        return new FunctionService(provider, new DirectThreadingStrategy());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void unresolvedFunctionReportsAnErrorRowNotAnErrorString() {
        Map<String, Object> b = body(service().batchDecompileFunctions("does_not_exist", ""));

        assertEquals(1, b.get("count"));
        assertEquals(1, b.get("total"));
        assertEquals(false, b.get("truncated"));
        assertFalse("no truncation happened - there must be no truncation_note",
            b.containsKey("truncation_note"));

        List<Map<String, Object>> results = (List<Map<String, Object>>) b.get("results");
        assertEquals(1, results.size());
        Map<String, Object> row = results.get(0);
        assertEquals("does_not_exist", row.get("function"));
        assertEquals("error", row.get("status"));
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

        Map<String, Object> b = body(service().batchDecompileFunctions(refs.toString(), ""));

        assertEquals("total must reflect everything requested, even the part dropped",
            25, b.get("total"));
        assertEquals("results must stop at MAX_FUNCTIONS, not silently continue or silently "
                + "stop short", 20, b.get("count"));
        assertEquals(true, b.get("truncated"));
        assertTrue("a truncated batch must explain itself", b.containsKey("truncation_note"));

        List<Map<String, Object>> results = (List<Map<String, Object>>) b.get("results");
        assertEquals(20, results.size());
    }

    @Test
    public void emptyFunctionsParameterIsRejectedUpFront() {
        Response r = service().batchDecompileFunctions("", "");
        assertTrue(r.toJson(), r instanceof Response.Err);
    }
}
