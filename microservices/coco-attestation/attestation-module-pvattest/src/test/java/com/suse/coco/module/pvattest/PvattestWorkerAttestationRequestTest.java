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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.suse.coco.model.AttestationConfigData;
import com.suse.coco.model.AttestationResult;
import com.suse.coco.model.AttestationStatus;
import com.suse.coco.module.pvattest.execution.PvattestWrapper;
import com.suse.common.utilities.JsonUtilities;

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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.concurrent.ExecutionException;

@ExtendWith(MockitoExtension.class)
public class PvattestWorkerAttestationRequestTest {

    @Mock
    private SqlSession session;

    @Mock
    private PvattestWrapper pvattestWrapper;

    private PvattestWrapper.AttestationRequest attestationRequest;

    private AttestationConfigData configData;
    private AttestationResult result;
    private PvattestWorker worker;

    @BeforeEach
    void setup() throws ExecutionException {
        configData = new AttestationConfigData();
        configData.setServerId(100L);
        configData.setInData(PvattestTestHelper.getConfigData());

        result = new AttestationResult();
        result.setId(1L);
        result.setStatus(AttestationStatus.PENDING);
        result.setReportId(5L);
        result.setInData(null);
        result.setOutData(null);

        attestationRequest = new PvattestWrapper.AttestationRequest(
                PvattestTestHelper.TEST_ATTESTATION_REQUEST_CONTENT_BASE_64,
                PvattestTestHelper.TEST_ATTESTATION_PROTECTION_KEY_CONTENT_BASE_64
        );

        // Common mocking
        when(session.selectOne("PvattestModule.retrieveConfigData", 5L)).thenReturn(configData);

        worker = new PvattestWorker(pvattestWrapper);
    }

    @Test
    @DisplayName("Rejects request if an exception is thrown")
    void rejectsWhenExceptionHappens() {

        when(session.selectOne("PvattestModule.retrieveConfigData", 5L))
                .thenThrow(PersistenceException.class);

        assertFalse(worker.processAttestationRequest(session, result));
        assertEquals("""
                        - Unable to create request: org.apache.ibatis.exceptions.PersistenceException
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @Test
    @DisplayName("Rejects request if configuration data is not found")
    void rejectsWhenConfigurationIsNotFound() {

        when(session.selectOne("PvattestModule.retrieveConfigData", 5L))
                .thenReturn(null);

        assertFalse(worker.processAttestationRequest(session, result));
        assertEquals("""
                        - Unable to retrieve configuration data for request
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"  "})
    @DisplayName("Rejects request if configuration data is empty")
    void rejectsWhenConfigurationIsNotFound(String inData) {
        configData.setInData(inData);

        assertFalse(worker.processAttestationRequest(session, result));
        assertEquals("""
                        - Unable to create request: configuration input data is empty
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"  "})
    @DisplayName("Rejects request if configuration host key document is empty or tag is not present")
    void rejectsWhenHkdIsEmptyOrTagNotPresent(String hkd) {

        configData.setInData(PvattestTestHelper.getConfigData(hkd, "dummySeh"));

        assertFalse(worker.processAttestationRequest(session, result));
        assertEquals("""
                        - Unable to create request: host key document not found
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @Test
    @DisplayName("Rejects request if configuration host key document is invalid")
    void rejectsWhenHkdIsNotValid() {

        configData.setInData(PvattestTestHelper.getConfigData("invalid_hkd", "dummySeh"));

        assertFalse(worker.processAttestationRequest(session, result));
        assertEquals("""
                        - Unable to create request: could not parse host key certificate
                        """,
                result.getProcessOutput()
        );

        verifyNoInteractions(pvattestWrapper);
    }

    @Test
    @DisplayName("Rejects request if configuration host key document is not parseable")
    void rejectsWhenHkdIsNotParseable() throws CertificateException, IOException, ExecutionException {
        PvattestWrapper realPvattestWrapper = new PvattestWrapper();
        worker = new PvattestWorker(realPvattestWrapper);

        configData.setInData(PvattestTestHelper.getConfigData(
                PvattestTestHelper.HOST_KEY_DOCUMENT.replace("S", "X"),
                "dummySeh"));

        assertFalse(worker.processAttestationRequest(session, result));
        assertTrue(result.getProcessOutput().startsWith("- Unable to create request:"));
    }

    @Test
    @DisplayName("Accept request if configuration host key document and secure execution header are valid")
    void acceptedWhenHdkAndSehAreValid() throws CertificateException, IOException, ExecutionException {

        when(pvattestWrapper.createVerifyDownloadCertificates(any()))
                .thenReturn(attestationRequest);

        assertTrue(worker.processAttestationRequest(session, result));

        Map<String, String> dataMap = JsonUtilities.decodeSimpleJsonString(result.getInData());

        assertTrue(dataMap.containsKey(PvattestWorker.ATTESTATION_REQUEST_BIN_TAG));
        assertEquals(PvattestTestHelper.TEST_ATTESTATION_REQUEST_CONTENT_BASE_64,
                dataMap.get(PvattestWorker.ATTESTATION_REQUEST_BIN_TAG));

        assertTrue(dataMap.containsKey(PvattestWorker.ATTESTATION_PROTECTION_KEY_TAG));
        assertEquals(PvattestTestHelper.TEST_ATTESTATION_PROTECTION_KEY_CONTENT_BASE_64,
                dataMap.get(PvattestWorker.ATTESTATION_PROTECTION_KEY_TAG));

        assertNull(result.getOutData());
        assertEquals("", result.getProcessOutput());
    }

}

