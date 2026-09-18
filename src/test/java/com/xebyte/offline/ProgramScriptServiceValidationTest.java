package com.xebyte.offline;

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import com.xebyte.core.SecurityConfig;
import com.xebyte.core.ThreadingStrategy;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import junit.framework.TestCase;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validation + guard coverage for ProgramScriptService (~2.3K LOC, previously only the
 * run-script propagation offline test). Exercises required-param guards, project-state guards,
 * headless project-file behavior, and the script-execution security gate.
 */
public class ProgramScriptServiceValidationTest extends TestCase {

    private ProgramScriptService scripts;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        scripts = new ProgramScriptService(ServiceFactory.stubProvider(), ts);
    }

    public void testCloseProgramRequiresName() {
        Response r = scripts.closeProgram("", true);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Program name or path is required"));
    }

    public void testSwitchProgramRequiresName() {
        Response r = scripts.switchProgram("");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Program name is required"));
    }

    public void testOpenProgramFromProjectRequiresPath() {
        Response r = scripts.openProgramFromProject("");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Program path is required"));
    }

    public void testImportFileRequiresFilePath() {
        Response r = scripts.importFile("", "/", "", "", true);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("file_path is required"));
    }

    public void testListProjectFilesRequiresOpenProject() {
        Response r = scripts.listProjectFiles("/");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("No project is currently open"));
    }

    public void testHeadlessImportDelegatesToProgramProvider() throws Exception {
        ProgramProvider provider = mock(ProgramProvider.class);
        Project project = mock(Project.class);
        when(provider.getProject()).thenReturn(project);

        Path input = Files.createTempFile("ghidra-headless-import-", ".bin");
        Files.write(input, new byte[]{0x01, 0x02, 0x03, 0x04});
        try {
            ProgramScriptService svc =
                new ProgramScriptService(provider, new NoopThreadingStrategy());

            Response r = svc.importFile(
                input.toFile().getAbsolutePath(), "/firmware", "", "", false);

            assertTrue(r instanceof Response.Err);
            assertTrue(((Response.Err) r).message().contains("Import failed in headless mode"));
            verify(provider).importProgram(
                any(File.class),
                org.mockito.ArgumentMatchers.eq("/firmware"),
                org.mockito.ArgumentMatchers.eq(""),
                org.mockito.ArgumentMatchers.eq(""));
        } finally {
            Files.deleteIfExists(input);
        }
    }

    public void testHeadlessListProjectFilesUsesProviderProject() {
        ProgramProvider provider = mock(ProgramProvider.class);
        Project project = mock(Project.class);
        ProjectData projectData = mock(ProjectData.class);
        DomainFolder root = mock(DomainFolder.class);

        when(provider.getProject()).thenReturn(project);
        when(project.getName()).thenReturn("headless-regression");
        when(project.getProjectData()).thenReturn(projectData);
        when(projectData.getRootFolder()).thenReturn(root);
        when(root.getPathname()).thenReturn("/");
        when(root.getFolders()).thenReturn(new DomainFolder[0]);
        when(root.getFiles()).thenReturn(new DomainFile[0]);

        ProgramScriptService svc =
            new ProgramScriptService(provider, new NoopThreadingStrategy());
        Response r = svc.listProjectFiles("/");

        assertTrue(r instanceof Response.Ok);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals("headless-regression", data.get("project_name"));
        assertEquals("/", data.get("current_folder"));
    }

    public void testHeadlessCreateFolderUsesProviderProject() throws Exception {
        ProgramProvider provider = mock(ProgramProvider.class);
        Project project = mock(Project.class);
        ProjectData projectData = mock(ProjectData.class);
        DomainFolder root = mock(DomainFolder.class);
        DomainFolder created = mock(DomainFolder.class);

        when(provider.getProject()).thenReturn(project);
        when(project.getProjectData()).thenReturn(projectData);
        when(projectData.getRootFolder()).thenReturn(root);
        when(root.getFolder("firmware")).thenReturn(null);
        when(root.createFolder("firmware")).thenReturn(created);
        when(created.getPathname()).thenReturn("/firmware");

        ProgramScriptService svc =
            new ProgramScriptService(provider, new NoopThreadingStrategy());
        Response r = svc.createFolder("/firmware", "");

        assertTrue(r instanceof Response.Ok);
        verify(root).createFolder("firmware");
    }

    public void testHeadlessDeleteFileClosesThroughProviderBeforeDelete() throws Exception {
        ProgramProvider provider = mock(ProgramProvider.class);
        Project project = mock(Project.class);
        ProjectData projectData = mock(ProjectData.class);
        DomainFile domainFile = mock(DomainFile.class);
        Program program = mock(Program.class);

        when(provider.getProject()).thenReturn(project);
        when(project.getProjectData()).thenReturn(projectData);
        when(projectData.getFile("/probe")).thenReturn(domainFile);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[]{program});
        when(program.getDomainFile()).thenReturn(domainFile);
        when(domainFile.getPathname()).thenReturn("/probe");
        when(provider.closeProgram(program)).thenReturn(true);

        ProgramScriptService svc =
            new ProgramScriptService(provider, new NoopThreadingStrategy());
        Response r = svc.deleteFile("/probe");

        assertTrue(r instanceof Response.Ok);
        verify(provider).closeProgram(program);
        verify(domainFile).delete();
    }

    public void testRunScriptInlineGatedByDefault() {
        if (!SecurityConfig.getInstance().areScriptsAllowed()) {
            Response r = scripts.runScriptInline("System.out.println(1);", "", "");
            assertTrue(r instanceof Response.Err);
            assertTrue(((Response.Err) r).message().contains("Script execution disabled"));
        }
    }
}
