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

package com.suse.coco.module.pvattest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.suse.coco.model.AttestationConfigData;
import com.suse.coco.model.AttestationResult;
import com.suse.coco.model.AttestationStatus;
import com.suse.coco.module.pvattest.execution.PvattestWrapper;

import org.apache.ibatis.exceptions.PersistenceException;
import org.apache.ibatis.session.SqlSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.concurrent.ExecutionException;

@ExtendWith(MockitoExtension.class)
class PvattestWorkerAttestationVerificationTest {

    @Mock
    private SqlSession session;

    @Mock
    private PvattestWrapper pvattestWrapper;

    @Mock
    private PvattestWrapper.AttestationResult verificationResult;

    private AttestationConfigData configData;
    private AttestationResult result;
    private PvattestWorker worker;

    private static final String INVALID_BASE64_STRING = "invalidBase64LenShouldBeAMultipleOf4=";


    @BeforeEach
    void setup() throws ExecutionException {
        configData = new AttestationConfigData();
        configData.setServerId(100L);
        configData.setInData(PvattestTestHelper.getConfigData());

        result = new AttestationResult();
        result.setId(1L);
        result.setStatus(AttestationStatus.PENDING);
        result.setReportId(5L);
        result.setInData(PvattestTestHelper.getInputData());
        result.setOutData(PvattestTestHelper.getOutData());

        verificationResult = new PvattestWrapper.AttestationResult(
                PvattestTestHelper.TEST_ATTESTATION_RESULT_YAML,
                PvattestTestHelper.TEST_RANDOM_USER_NONCE);

        // Common mocking
        when(session.selectOne("PvattestModule.retrieveConfigData", 5L)).thenReturn(configData);

        worker = new PvattestWorker(pvattestWrapper);
    }

    @Test
    @DisplayName("Rejects verification if an exception is thrown")
    void rejectsWhenExceptionHappens() {

        when(session.selectOne("PvattestModule.retrieveConfigData", 5L))
                .thenThrow(PersistenceException.class);

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to process attestation result: org.apache.ibatis.exceptions.PersistenceException
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @Test
    @DisplayName("Rejects verification if configuration data is not found")
    void rejectsWhenConfigurationIsNotFound() {

        when(session.selectOne("PvattestModule.retrieveConfigData", 5L))
                .thenReturn(null);

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to retrieve configuration data for result
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"  "})
    @DisplayName("Rejects verification if configuration data is empty or tag is not present")
    void rejectsWhenConfigurationIsEmptyOrTagNotPresent(String inData) {

        configData.setInData(inData);

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to retrieve configuration data: empty configuration data
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"  "})
    @DisplayName("Rejects verification if configuration secure extension header is empty or tag is not present")
    void rejectsWhenSehIsEmptyOrTagNotPresent(String seh) {

        configData.setInData(PvattestTestHelper.getConfigData("dummyHKD", seh));

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to verify: secure extension header not found in configuration
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @Test
    @DisplayName("Rejects verification if configuration secure extension header is not base64")
    void rejectsWhenSehIsNotBase64() {
        configData.setInData(PvattestTestHelper.getConfigData("dummyHKD", INVALID_BASE64_STRING));

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to verify: invalid base64 secure extension header in configuration
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }


    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"  "})
    @DisplayName("Rejects verification if attestation response is empty or tag is not present")
    void rejectsWhenAttestationResultIsEmptyOrTagNotPresent(String attResult) {

        result.setOutData(PvattestTestHelper.getOutData(attResult));

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to verify: attestation response not found in output
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @Test
    @DisplayName("Rejects verification if attestation response is not base64")
    void rejectsWhenAttestationResultIsNotBase64() {

        result.setOutData(PvattestTestHelper.getOutData(INVALID_BASE64_STRING));

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to verify: invalid base64 attestation response in output
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"  "})
    @DisplayName("Rejects verification if attestation protection key is empty or tag is not present")
    void rejectsWhenAttestationProtectionKeyIsEmptyOrTagNotPresent(String attResult) {

        result.setInData(PvattestTestHelper.getInputData("dummyNonce", "dummyAttRequest", attResult));

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to verify: attestation protection key not found in input
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @Test
    @DisplayName("Rejects verification if attestation protection key is not base64")
    void rejectsWhenAttestationProtectionKeyIsNotBase64() {
        result.setOutData(PvattestTestHelper.getOutData());

        result.setInData(PvattestTestHelper.getInputData("dummyNonce", "dummyAttRequest",
                INVALID_BASE64_STRING));

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to verify: invalid base64 attestation protection key in input
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"  "})
    @DisplayName("Rejects verification if nonce is empty or tag is not present")
    void rejectsWhenNonceIsEmptyOrTagNotPresent(String nonce) {

        result.setInData(PvattestTestHelper.getInputData(nonce, "dummyAttRequest", "dummyAttResult"));

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to verify: nonce not found in input
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @Test
    @DisplayName("Rejects verification if attestation response tag is empty")
    void rejectsWhenAttestationResultIsEmpty() {

        result.setOutData(PvattestTestHelper.getOutData(" "));

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to verify: attestation response not found in output
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @Test
    @DisplayName("Rejects verification if the verification process throws an exception")
    void rejectsWhenVerificationThrows() throws ExecutionException {

        when(pvattestWrapper.verifyAttestationReport(any(), any(), any()))
                .thenThrow(ExecutionException.class);

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to process attestation result: java.util.concurrent.ExecutionException
                        """,
                result.getProcessOutput()
        );

    }

    @Test
    @DisplayName("Rejects verification if the verification process fails")
    void rejectsWhenVerificationProcessFails() throws ExecutionException {

        PvattestWrapper.AttestationResult res = new PvattestWrapper.AttestationResult(
                null,
                PvattestTestHelper.TEST_RANDOM_USER_NONCE);
        when(pvattestWrapper.verifyAttestationReport(any(), any(), any()))
                .thenReturn(res);

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to verify: verification failed
                        """,
                result.getProcessOutput()
        );
    }


    @Test
    @DisplayName("Rejects verification if verification nonce is not matching")
    void rejectsWhenNonceNotMatching() throws ExecutionException {
        PvattestWrapper.AttestationResult res = new PvattestWrapper.AttestationResult(
                PvattestTestHelper.TEST_ATTESTATION_RESULT_YAML,
                "NOT MATCHING NONCE");
        when(pvattestWrapper.verifyAttestationReport(any(), any(), any()))
                .thenReturn(res);

        assertFalse(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Unable to verify: nonce not matching
                        """,
                result.getProcessOutput()
        );
    }


    //suppress checkstyle warnings in order to keep it as it appears in the file
    @SuppressWarnings("checkstyle:lineLength")
    @Test
    @DisplayName("Approves verification if all checks pass")
    void approvesVerificationIfAllChecksPass() throws ExecutionException {

        when(pvattestWrapper.verifyAttestationReport(any(), any(), any()))
                .thenReturn(verificationResult);

        assertTrue(worker.processAttestationVerification(session, result));
        assertEquals("""
                        - Attestation report correctly verified
                        """,
                result.getProcessOutput()
        );

        assertEquals("""
                        cuid: '0x3eb912539634cdce660ab840209190e2'
                        add: 0xd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83cd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83c
                        add_fields:
                          image_phkh: 0xd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83c
                          attestation_phkh: 0xd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83c
                        user_data: 0x72616e646f6d2075736572206461746120666f72207374616e646172645f617474656d70745f355f30335f31360a
                        """,
                result.getDetails()
        );
    }

}
