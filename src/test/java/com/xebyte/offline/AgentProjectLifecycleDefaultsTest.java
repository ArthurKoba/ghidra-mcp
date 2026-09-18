package com.xebyte.offline;

import com.xebyte.core.McpTool;
import com.xebyte.core.Param;
import com.xebyte.headless.HeadlessManagementService;
import junit.framework.TestCase;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

public class AgentProjectLifecycleDefaultsTest extends TestCase {
    private static Method tool(String name) {
        for (Method method : HeadlessManagementService.class.getDeclaredMethods()) {
            if (method.getName().equals(name) && method.isAnnotationPresent(McpTool.class)) return method;
        }
        fail("missing tool " + name);
        return null;
    }

    private static Param param(Method method, String name) {
        for (Parameter p : method.getParameters()) {
            Param ann = p.getAnnotation(Param.class);
            if (ann != null && name.equals(ann.value())) return ann;
        }
        fail("missing param " + name);
        return null;
    }

    public void testStorageInfoEndpointIsRegistered() {
        Method storage = tool("getStorageInfo");
        assertEquals("/get_storage_info", storage.getAnnotation(McpTool.class).path());
        assertEquals("headless", storage.getAnnotation(McpTool.class).category());
    }

    public void testCreateProjectUsesConfiguredRootWhenParentEmpty() {
        assertEquals("", param(tool("createProject"), "parentDir").defaultValue());
        assertTrue(tool("createProject").getAnnotation(McpTool.class).description()
                .contains("Server credentials are not required"));
    }

    public void testExportsDefaultToArtifactVolume() {
        assertEquals("/artifacts/exports", param(tool("exportProgram"), "output_dir").defaultValue());
        assertEquals("/artifacts/exports", param(tool("archiveProject"), "output_dir").defaultValue());
    }

    public void testRestoreUsesConfiguredProjectRootWhenParentEmpty() {
        assertEquals("", param(tool("restoreProject"), "parent_dir").defaultValue());
    }
}
