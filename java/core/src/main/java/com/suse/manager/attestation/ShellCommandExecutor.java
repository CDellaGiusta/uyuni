/*
 * Copyright (c) 2026 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 */

package com.suse.manager.attestation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ShellCommandExecutor {
    public record ProcessOutput(int exitCode, String standardOutput, String standardError) {
        public boolean succeeded() {
            return 0 == exitCode;
        }

        public boolean failed() {
            return 0 != exitCode;
        }

        public String getErrorMessage() {
            int maxMessageLength = 2300;
            String msg = standardError;
            if (msg.isBlank()) {
                msg = standardOutput;
            }

            if (msg.length() > maxMessageLength) {
                return "... " + msg.substring(standardError.length() - maxMessageLength);
            }
            else {
                return msg;
            }
        }
    }

    private static final Logger LOGGER = LogManager.getLogger(ShellCommandExecutor.class);
    private final Runtime runtime;
    protected String lastExecutedCommand;

    public ShellCommandExecutor() {
        runtime = Runtime.getRuntime();
        lastExecutedCommand = "";
    }

    public String getLastExecutedCommand() {
        return lastExecutedCommand;
    }

    protected ProcessOutput executeProcess(String... command) throws ExecutionException {
        lastExecutedCommand = String.join(" ", command);

        Process process;
        try {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Executing {}", Arrays.toString(command));
            }

            process = runtime.exec(command);
        }
        catch (IOException ex) {
            throw new ExecutionException("Unable to create snpguest process", ex);
        }

        ExecutorService executor = Executors.newFixedThreadPool(2);

        try {
            int exitCode = process.waitFor();

            String standardOutputIn = getOutput(process.getInputStream(), "stdout");
            String standardErrorIn = getOutput(process.getErrorStream(), "stderr");

            return new ProcessOutput(
                    exitCode,
                    standardOutputIn,
                    standardErrorIn
            );
        }
        catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new ExecutionException("Unable to get process execution result", ex);
        }
        catch (IOException ex) {
            throw new ExecutionException("Unable to get process execution output", ex);
        }
        finally {
            executor.shutdown();
        }
    }

    private String getOutput(InputStream stream, String logPrefix) throws IOException {
        StringWriter writer = new StringWriter();

        try (BufferedReader inErr = new BufferedReader(new InputStreamReader(stream))) {
            String line;
            while ((line = inErr.readLine()) != null) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(logPrefix, line);
                }

                writer.write(line);
                writer.write(System.lineSeparator());
            }

            return writer.toString();
        }
    }
}
