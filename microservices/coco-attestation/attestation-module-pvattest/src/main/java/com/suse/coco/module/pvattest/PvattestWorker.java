/*
 * Copyright (c) 2024 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 */

package com.suse.coco.module.pvattest;

import com.suse.coco.model.AttestationConfigData;
import com.suse.coco.model.AttestationResult;
import com.suse.coco.module.AttestationWorker;
import com.suse.coco.module.pvattest.execution.PvattestWrapper;
import com.suse.common.utilities.CertificateHelper;
import com.suse.common.utilities.JsonUtilities;
import com.suse.common.utilities.ShellCommandExecutor;

import org.apache.ibatis.session.SqlSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * Worker class for verifying the reports with SNPGuest
 */
public class PvattestWorker implements AttestationWorker {

    private static final Logger LOGGER = LogManager.getLogger(PvattestWorker.class);

    private static final int INDENT_SIZE = 4;

    private final PvattestWrapper pvattest;

    private final StringBuilder outputBuilder;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Default constructor.
     */
    public PvattestWorker() {
        this(new PvattestWrapper());
    }

    /**
     * Constructor with explicit dependencies, for unit test only.
     *
     * @param pvattestWrapperIn the pvattest executor
     */
    PvattestWorker(PvattestWrapper pvattestWrapperIn) {
        this.pvattest = pvattestWrapperIn;
        this.outputBuilder = new StringBuilder();
    }

    public static final String HOST_KEY_DOCUMENT_TAG = "host_key_document";
    public static final String SECURE_EXECUTION_HEADER_TAG = "secure_execution_header";

    public static final String NONCE_TAG = "nonce";
    public static final String ATTESTATION_REQUEST_BIN_TAG = "attestation_request";
    public static final String ATTESTATION_PROTECTION_KEY_TAG = "attestation_protection_key";
    public static final String ATTESTATION_RESPONSE_BIN_TAG = "attestation_response";


    private boolean isEmptyString(String str) {
        return (null == str || str.isBlank());
    }

    @Override
    public boolean processAttestationRequest(SqlSession session, AttestationResult result) {
        // Reset the output string builder
        outputBuilder.setLength(0);

        try {
            LOGGER.debug("Processing attestation request {}", result.getId());

            //retrieve json configuration data input from configuration table
            AttestationConfigData configData = session.selectOne(
                    "PvattestModule.retrieveConfigData", result.getReportId());
            if (configData == null) {
                appendError("Unable to retrieve configuration data for request");
                return false;
            }

            LOGGER.debug("Loaded configData {}", configData);
            if (isEmptyString(configData.getInData())) {
                appendError("Unable to create request: configuration input data is empty");
                return false;
            }

            Map<String, String> map = JsonUtilities.decodeSimpleJsonString(configData.getInData());

            //retrieve and parse host key document
            if (!map.containsKey(HOST_KEY_DOCUMENT_TAG) || isEmptyString(map.get(HOST_KEY_DOCUMENT_TAG))) {
                appendError("Unable to create request: host key document not found");
                return false;
            }

            //create attestation request
            String hostKeyDocumentContent = map.get(HOST_KEY_DOCUMENT_TAG).replace("\\n", "\n");

            try {
                CertificateHelper.parse(hostKeyDocumentContent);
            }
            catch (CertificateException eIn) {
                appendError("Unable to create request: could not parse host key certificate");
                return false;
            }

            PvattestWrapper.AttestationRequest attestationRequest =
                    pvattest.createVerifyDownloadCertificates(hostKeyDocumentContent);

            //compute attestation request data

            //add attestationRequest binary
            String attestationRequestData = JsonUtilities.createJson(ATTESTATION_REQUEST_BIN_TAG,
                    attestationRequest.base64AttestationRequest());

            //add attestationRequest protection key
            attestationRequestData = JsonUtilities.addToJson(attestationRequestData, ATTESTATION_PROTECTION_KEY_TAG,
                    attestationRequest.base64AttestationProtectionKey());

            //create and add nonce
            int nonceLength = 256;
            byte[] bytes = new byte[nonceLength];
            secureRandom.nextBytes(bytes);
            String nonceString = Base64.getEncoder().encodeToString(bytes);

            attestationRequestData = JsonUtilities.addToJson(attestationRequestData, NONCE_TAG, nonceString);

            //set and save attestation request data
            result.setInData(attestationRequestData);
            return true;
        }
        catch (Exception ex) {
            String exceptionMessage = Optional.ofNullable(ex.getMessage()).orElse(ex.getClass().getName());
            appendError("Unable to create request: " + exceptionMessage, ex);
        }
        finally {
            result.setProcessOutput(outputBuilder.toString());
        }

        return false;
    }

    private Optional<String> retrieveBase64String(Map<String, String> retrieveMap, String tagKey,
                                                  String errorSubject, String errorWhere) {
        if (!retrieveMap.containsKey(tagKey) || isEmptyString(retrieveMap.get(tagKey))) {
            appendError("Unable to verify: %s not found in %s".formatted(errorSubject, errorWhere));
            return Optional.empty();
        }
        String base64EncodedContent = retrieveMap.get(tagKey).replace("\n", "");

        try {
            Base64.getDecoder().decode(base64EncodedContent);
        }
        catch (Exception ex) {
            appendError("Unable to verify: invalid base64 %s in %s".formatted(errorSubject, errorWhere));
            return Optional.empty();
        }

        return Optional.of(base64EncodedContent);
    }

    @Override
    public boolean processAttestationVerification(SqlSession session, AttestationResult result) {
        // Reset the output string builder
        outputBuilder.setLength(0);

        try {
            Optional<String> optString;

            LOGGER.debug("Processing attestation response {}", result.getId());

            //retrieve json configuration data input from configuration table
            AttestationConfigData configData = session.selectOne(
                    "PvattestModule.retrieveConfigData", result.getReportId());
            if (configData == null) {
                appendError("Unable to retrieve configuration data for result");
                return false;
            }

            LOGGER.debug("Loaded configData {}", configData);
            if (isEmptyString(configData.getInData())) {
                appendError("Unable to retrieve configuration data: empty configuration data");
                return false;
            }

            Map<String, String> configurationMap = JsonUtilities.decodeSimpleJsonString(configData.getInData());
            Map<String, String> resultOutMap = JsonUtilities.decodeSimpleJsonString(result.getOutData());
            Map<String, String> resultInMap = JsonUtilities.decodeSimpleJsonString(result.getInData());

            //retrieve and parse secure extension header from configuration
            optString = retrieveBase64String(configurationMap, SECURE_EXECUTION_HEADER_TAG,
                    "secure extension header", "configuration");
            if (optString.isEmpty()) {
                return false;
            }
            String secureExecutionHeaderContentBase64 = optString.get();

            //retrieve and parse attestation response from output
            optString = retrieveBase64String(resultOutMap, ATTESTATION_RESPONSE_BIN_TAG,
                    "attestation response", "output");
            if (optString.isEmpty()) {
                return false;
            }
            String attestationReportContentBase64 = optString.get();

            //retrieve and parse attestation protection key from input
            optString = retrieveBase64String(resultInMap, ATTESTATION_PROTECTION_KEY_TAG,
                    "attestation protection key", "input");
            if (optString.isEmpty()) {
                return false;
            }
            String attestationProtectionKeyContentBase64 = optString.get();

            //retrieve and parse nonce from input
            if (!resultInMap.containsKey(NONCE_TAG) || isEmptyString(resultInMap.get(NONCE_TAG))) {
                appendError("Unable to verify: nonce not found in input");
                return false;
            }
            String nonce = resultInMap.get(NONCE_TAG);

            // Verify the actual attestation report
            PvattestWrapper.AttestationResult verificationResult =
                    pvattest.verifyAttestationReport(attestationReportContentBase64,
                            secureExecutionHeaderContentBase64,
                            attestationProtectionKeyContentBase64);

            if (verificationResult.failed()) {
                appendError("Unable to verify: verification failed");
                return false;
            }

            String attestationResultContent = verificationResult.attestationResultContent();
            String randomUserNonceResultContent = verificationResult.randomUserNonceResultContent();

            if (!randomUserNonceResultContent.equals(nonce)) {
                appendError("Unable to verify: nonce not matching");
                return false;
            }

            appendSuccess("Attestation report correctly verified");
            result.setDetails(attestationResultContent);

            return true;
        }
        catch (Exception ex) {
            String exceptionMessage = Optional.ofNullable(ex.getMessage()).orElse(ex.getClass().getName());
            appendError("Unable to process attestation result: " + exceptionMessage, ex);
        }
        finally {
            result.setProcessOutput(outputBuilder.toString());
        }

        return false;
    }

    private void appendError(String message) {
        appendOutput(message, null);
        LOGGER.error(message);
    }

    private void appendError(String message, Exception ex) {
        appendOutput(message, null);
        LOGGER.error(message, ex);
    }

    private void appendSuccess(String message) {
        appendOutput(message, null);
    }

    private void appendSuccess(String message, ShellCommandExecutor.ProcessOutput output) {
        appendOutput(message, output);
    }

    private void appendOutput(String message, ShellCommandExecutor.ProcessOutput processOutput) {
        outputBuilder.append("- ").append(message);

        String processDetails = getProcessOutputDetails(processOutput);
        if (!processDetails.isEmpty()) {
            outputBuilder.append(":")
                    .append(System.lineSeparator())
                    .append(processDetails);
        }
        else {
            outputBuilder.append(System.lineSeparator());
        }
    }

    private static String getProcessOutputDetails(ShellCommandExecutor.ProcessOutput processOutput) {
        if (processOutput == null) {
            return "";
        }

        StringBuilder processBuilder = new StringBuilder();
        if (processOutput.exitCode() != 0) {
            processBuilder.append("- Exit code: %d".formatted(processOutput.exitCode()).indent(INDENT_SIZE));
        }

        if (processOutput.hasStandardOutput()) {
            processBuilder.append("- Standard output: >".indent(INDENT_SIZE));
            processBuilder.append(processOutput.standardOutput().indent(INDENT_SIZE * 2));
        }

        if (processOutput.hasStandardError()) {
            processBuilder.append("- Standard error: >".indent(INDENT_SIZE));
            processBuilder.append(processOutput.standardError().indent(INDENT_SIZE * 2));
        }

        return processBuilder.toString();
    }
}
