package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * Regression coverage for the /disassemble_bytes fix: restrict_to_execute_memory
 * and follow_flow used to be conflated into a single boolean passed straight to
 * DisassembleCommand's followFlow argument, with a null restrictedSet. That meant
 * the documented-safe default (restrict_to_execute_memory=true) actually turned on
 * UNBOUNDED flow-following with NO restriction at all, inside a committed
 * transaction - the opposite of what "restrict" promised.
 */
public class FunctionServiceDisassembleBytesGhidraTest {

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
        builder = new ProgramBuilder("disassemble-bytes", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x1100);

        // Requested range: 0x1000-0x1004 is a near CALL to 0x2000.
        // CALL 0x2000 (5 bytes)
        builder.setBytes("0x1000", "e8 fb 0f 00 00");
        // Callee, well outside the requested range: TEST EAX,EAX; RET
        builder.setBytes("0x2000", "85 c0 c3");
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void defaultsStayWithinTheRequestedRange() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        FunctionService service = new FunctionService(provider, new DirectThreadingStrategy());

        // follow_flow defaults to false via the back-compat overload used by the
        // headless/plugin call sites, and via the tool's own defaultValue="false".
        Response response = service.disassembleBytes("0x1000", null, 5, true);

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertNotNull("requested range was not disassembled",
            program.getListing().getInstructionAt(builder.addr("0x1000")));
        assertNull("follow_flow=false must not disassemble past the requested range - "
                + "this is the exact unbounded-mutation bug being regression-tested",
            program.getListing().getInstructionAt(builder.addr("0x2000")));
    }

    @Test
    public void followFlowExplicitlyRequestedReachesTheCallTarget() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        FunctionService service = new FunctionService(provider, new DirectThreadingStrategy());

        Response response = service.disassembleBytes("0x1000", null, 5, true, true, true, 1000, "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        Instruction callee = program.getListing().getInstructionAt(builder.addr("0x2000"));
        assertNotNull("follow_flow=true should have followed the CALL to its target", callee);
    }

    @Test
    public void restrictToExecuteMemoryFalseDoesNotImplyFollowFlow() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        FunctionService service = new FunctionService(provider, new DirectThreadingStrategy());

        // Before the fix, restrict_to_execute_memory alone controlled followFlow.
        // Setting it false must not, by itself, cause flow-following either -
        // the two are independent parameters now.
        Response response = service.disassembleBytes("0x1000", null, 5, false, false, true, 1000, "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertNull("restrict_to_execute_memory=false must not imply follow_flow=true",
            program.getListing().getInstructionAt(builder.addr("0x2000")));
    }
}
