/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.core;

import java.io.File;
import ghidra.program.model.listing.Program;

/**
 * Interface for providing access to Ghidra programs.
 *
 * This abstraction allows the MCP core to work in both GUI mode
 * (via ProgramManager) and headless mode (via direct program management).
 */
public interface ProgramProvider {

    /**
     * Get the currently active program.
     *
     * @return The current program, or null if no program is open
     */
    Program getCurrentProgram();

    /**
     * Get a program by its name.
     *
     * @param name The program name to look up
     * @return The matching program, or null if not found
     */
    Program getProgram(String name);

    /**
     * Get all currently open programs.
     *
     * @return Array of all open programs (may be empty, never null)
     */
    Program[] getAllOpenPrograms();

    /**
     * Set the current program.
     *
     * @param program The program to make current
     */
    void setCurrentProgram(Program program);

    /**
     * Close a program when the provider owns the program lifecycle.
     *
     * <p>GUI providers usually close through Ghidra's ProgramManager, so the
     * default is a no-op. Headless providers should override this.
     *
     * @param program The program to close
     * @return true if the provider closed the program
     */
    default boolean closeProgram(Program program) {
        return false;
    }

    /**
     * Check if any program is currently open.
     *
     * @return true if at least one program is open
     */
    default boolean hasOpenProgram() {
        return getCurrentProgram() != null;
    }

    /**
     * Get the project this provider is serving programs from.
     *
     * <p>GUI providers reach the project through their PluginTool, so the
     * default is null and callers fall back to the tool. Headless providers
     * own a Project directly and should override this — without it, project
     * -level tools (move/create/delete) would be GUI-only, which is exactly
     * the regression that converting {@code /move_file} to an {@code @McpTool}
     * would otherwise have introduced.
     *
     * @return The active project, or null if this provider has no direct handle
     */
    default ghidra.framework.model.Project getProject() {
        return null;
    }

    /**
     * Import a binary into this provider's active project.
     *
     * <p>The provider owns the imported Program's lifecycle. This matters in
     * headless mode where there is no PluginTool/ProgramManager consumer and
     * the provider itself must retain and eventually release the Program.
     *
     * @param file source file on the local Ghidra host
     * @param projectFolder destination folder in the active project
     * @param languageId optional explicit Ghidra language ID; blank means auto-detect
     * @param compilerSpecId optional compiler spec ID
     * @return imported/opened Program, or null when import failed
     * @throws UnsupportedOperationException when this provider cannot import files
     */
    default Program importProgram(File file, String projectFolder,
            String languageId, String compilerSpecId) {
        throw new UnsupportedOperationException("Binary import is not supported by this program provider");
    }

    /**
     * Get a program by name, falling back to current program if name is null or empty.
     *
     * @param name The program name (may be null)
     * @return The resolved program
     */
    default Program resolveProgram(String name) {
        if (name == null || name.isEmpty()) {
            return getCurrentProgram();
        }
        Program program = getProgram(name);
        return program != null ? program : getCurrentProgram();
    }
}
