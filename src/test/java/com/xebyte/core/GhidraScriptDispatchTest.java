package com.xebyte.core;

import junit.framework.TestCase;

import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Verifies that headless MCP script execution never enters the Swing EDT.
 * A full GhidraScript may compile, decompile or manage its own transaction;
 * blocking the Swing EDT for the whole run can deadlock those operations.
 */
public class GhidraScriptDispatchTest extends TestCase {

    public void testHeadlessExecutesOnTheRequestThread() throws Exception {
        ThreadingStrategy headless = mock(ThreadingStrategy.class);
        when(headless.isHeadless()).thenReturn(true);
        Thread requestThread = Thread.currentThread();
        AtomicReference<Thread> executionThread = new AtomicReference<>();

        ProgramScriptService.dispatchGhidraScript(headless,
                () -> executionThread.set(Thread.currentThread()));

        assertSame("Headless GhidraScript must run on the request thread",
                requestThread, executionThread.get());
        assertFalse("This test must start outside Swing EDT",
                SwingUtilities.isEventDispatchThread());
    }

    public void testGuiDispatchesToSwingEdt() throws Exception {
        ThreadingStrategy gui = mock(ThreadingStrategy.class);
        when(gui.isHeadless()).thenReturn(false);
        AtomicReference<Thread> executionThread = new AtomicReference<>();
        AtomicReference<Boolean> isEdt = new AtomicReference<>(false);

        ProgramScriptService.dispatchGhidraScript(gui, () -> {
            executionThread.set(Thread.currentThread());
            isEdt.set(SwingUtilities.isEventDispatchThread());
        });

        assertTrue("GUI GhidraScript should run on EDT", isEdt.get());
        assertNotSame("GUI GhidraScript must dispatch from this request thread",
                Thread.currentThread(), executionThread.get());
    }

    public void testGuiDoesNotInvokeAndWaitWhenAlreadyOnEdt() throws Exception {
        ThreadingStrategy gui = mock(ThreadingStrategy.class);
        when(gui.isHeadless()).thenReturn(false);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                ProgramScriptService.dispatchGhidraScript(gui, () ->
                        assertTrue(SwingUtilities.isEventDispatchThread()));
            } catch (Throwable e) {
                failure.set(e);
            }
        });
        if (failure.get() != null) {
            throw new AssertionError("GUI dispatch on EDT must not deadlock", failure.get());
        }
    }

    public void testHeadlessExceptionPropagates() throws Exception {
        ThreadingStrategy headless = mock(ThreadingStrategy.class);
        when(headless.isHeadless()).thenReturn(true);
        try {
            ProgramScriptService.dispatchGhidraScript(headless, () -> {
                throw new IllegalStateException("script rejected invalid PCM state");
            });
            fail("Expected script error");
        } catch (IllegalStateException expected) {
            assertEquals("script rejected invalid PCM state", expected.getMessage());
        }
    }
}
