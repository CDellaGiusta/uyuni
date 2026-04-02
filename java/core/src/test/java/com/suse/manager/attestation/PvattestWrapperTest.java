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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redhat.rhn.common.RhnRuntimeException;
import com.redhat.rhn.testing.MockObjectTestCase;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;

public class PvattestWrapperTest extends MockObjectTestCase {

    public static class MockShellCommandExecutor extends ShellCommandExecutor {
        private ShellCommandExecutor.ProcessOutput output;
        private boolean doFillFilesForCreate;
        private boolean doFillFilesForVerifyMeasurement;

        public void forceOutput(String standardOutput) {
            output = new ShellCommandExecutor.ProcessOutput(0, standardOutput, "");
        }

        private static void fillFile(String filename, int numBytes) {
            try {
                FileOutputStream outputStream = new FileOutputStream(filename);
                byte[] buffer = new byte[numBytes];
                outputStream.write(buffer);
                outputStream.close();
            }
            catch (IOException eIn) {
                throw new RuntimeException(eIn);
            }
        }

        private static void fillFile(String filename, String content) {
            try {
                Files.writeString(Path.of(filename), content, StandardCharsets.UTF_8);
            }
            catch (IOException eIn) {
                throw new RuntimeException(eIn);
            }
        }

        private void fillFilesForCreate(String... command) {
            for (String commandChunk : command) {
                if (commandChunk.contains("attestation_request_")) {
                    fillFile(commandChunk, 464);
                }
                if (commandChunk.contains("attestation_protection_key_")) {
                    fillFile(commandChunk, 32);
                }
            }
        }

        private void fillFilesForVerifyMeasurement(String... command) {
            for (String commandChunk : command) {
                if (commandChunk.contains("attestation_result_")) {
                    fillFile(commandChunk, TEST_ATTESTATION_RESULT_YAML);
                }
                if (commandChunk.contains("random_user_nonce_result_")) {
                    fillFile(commandChunk, TEST_RANDOM_USER_NONCE);
                }
            }
        }

        @Override
        protected ShellCommandExecutor.ProcessOutput executeProcess(String... command) throws ExecutionException {
            lastExecutedCommand = String.join(" ", command);

            if (doFillFilesForCreate) {
                fillFilesForCreate(command);
                doFillFilesForCreate = false;
            }

            if (doFillFilesForVerifyMeasurement) {
                fillFilesForVerifyMeasurement(command);
                doFillFilesForVerifyMeasurement = false;
            }

            return output;
        }
    }

    private final MockShellCommandExecutor mockCommandExecutor = new MockShellCommandExecutor();
    private final PvattestWrapper testPvattestWrapper = new PvattestWrapper(mockCommandExecutor);

    @Test
    @DisplayName("command check: findPackageVersion")
    public void testFindPackageVersion() throws ExecutionException {
        mockCommandExecutor.forceOutput("2.41.0\n");
        checkFindPackageVersion(testPvattestWrapper);
    }

    private void checkFindPackageVersion(PvattestWrapper pvaw) throws ExecutionException {
        assertEquals("2.41.0", pvaw.findPackageVersion());
        assertEquals("/usr/bin/rpm -q --queryformat %{VERSION} s390-tools", pvaw.getLastExecutedCommand());
    }

    @Test
    @DisplayName("command check: pvattest version")
    public void testVersion() throws ExecutionException {
        mockCommandExecutor.forceOutput("pvattest version 2.41.0-4\nCopyright IBM Corp. 2024\n");
        checkVersion(testPvattestWrapper);
    }

    private void checkVersion(PvattestWrapper pvaw) throws ExecutionException {
        assertEquals("2.41.0-4", pvaw.version());
        assertEquals("pvattest --version", pvaw.getLastExecutedCommand());
    }

    @Test
    @DisplayName("command check: pvattest create (no verify)")
    public void testCreateNoVerify() throws ExecutionException, CertificateException {
        mockCommandExecutor.forceOutput("""
                Host-key document verification is disabled. The attestation request may not be protected.\n
                Use host-key document at 'input/host_key_document.crt'\n
                Successfully generated the request\n""");
        mockCommandExecutor.doFillFilesForCreate = true;
        checkCreateNoVerify(testPvattestWrapper);
        checkCreateNoVerifyCommand(testPvattestWrapper);
    }

    private void checkCreateNoVerify(PvattestWrapper pvaw) throws ExecutionException, CertificateException {
        PvattestWrapper.AttestationRequest result = pvaw.createNoVerify(TEST_CERTIFICATE_2024_07_14);
        assertTrue(result.succeeded());
        assertEquals(44, result.base64AttestationProtectionKey().length());
        assertEquals(620, result.base64AttestationRequest().length());
    }

    private void checkCreateNoVerifyCommand(PvattestWrapper pvaw) {
        String command = pvaw.getLastExecutedCommand();

        assertTrue(command.startsWith("pvattest create -v "));
        assertTrue(command.contains(" -k "));
        assertTrue(command.contains(" -o "));
        assertTrue(command.contains(" -a "));
        assertTrue(command.contains(" --add-data phkh-img "));
        assertTrue(command.contains(" --add-data phkh-att"));

        assertTrue(command.contains(" --no-verify "));
        assertFalse(command.contains(" -C "));
    }

    @Test
    @DisplayName("command check: pvattest create (and verify) with certificate downloading")
    public void testCreateVerifyDownloadCertificates() throws ExecutionException, CertificateException, IOException {
        mockCommandExecutor.forceOutput("""
                Host-key document verification is disabled. The attestation request may not be protected.\n
                Use host-key document at 'input/host_key_document.crt'\n
                Successfully generated the request\n""");
        mockCommandExecutor.doFillFilesForCreate = true;
        checkCreateVerifyDownloadCertificatesOK(testPvattestWrapper);
        checkCreateVerifyDownloadCertificatesCommand(testPvattestWrapper);
    }

    private void checkCreateVerifyDownloadCertificatesOK(PvattestWrapper pvaw)
            throws ExecutionException, CertificateException, IOException {
        PvattestWrapper.AttestationRequest result = pvaw.createVerifyDownloadCertificates(TEST_CERTIFICATE_2024_07_14);
        assertTrue(result.succeeded());
        assertEquals(44, result.base64AttestationProtectionKey().length());
        assertEquals(620, result.base64AttestationRequest().length());
    }

    private void checkCreateVerifyDownloadCertificatesKO(PvattestWrapper pvaw) {
        assertThrows(RhnRuntimeException.class,
                () -> pvaw.createVerifyDownloadCertificates(TEST_CERTIFICATE_2024_07_14),
                "error: Host-key verification failed: After validity period");
    }

    private void checkCreateVerifyDownloadCertificatesCommand(PvattestWrapper pvaw) {
        String command = pvaw.getLastExecutedCommand();

        assertTrue(command.startsWith("pvattest create -v "));
        assertTrue(command.contains(" -k "));
        assertTrue(command.contains(" -o "));
        assertTrue(command.contains(" -a "));
        assertTrue(command.contains(" --add-data phkh-img "));
        assertTrue(command.contains(" --add-data phkh-att"));

        assertFalse(command.contains(" --no-verify "));
        assertTrue(command.contains(" -C "));
    }


    @Test
    @DisplayName("command check: pvattest verify")
    public void testVerifyAttestationReport() throws ExecutionException {
        mockCommandExecutor.forceOutput(TEST_ATTESTATION_REPORT_OUTPUT);
        mockCommandExecutor.doFillFilesForVerifyMeasurement = true;
        checkVerifyAttestationReportOK(testPvattestWrapper);
        checkVerifyAttestationReportCommand(testPvattestWrapper);
    }

    private void checkVerifyAttestationReportOK(PvattestWrapper pvaw) throws ExecutionException {
        PvattestWrapper.AttestationResult result =
                pvaw.verifyAttestationReport(TEST_ATTESTATION_RESULT_CONTENT_BASE_64.replace("\n", ""),
                        TEST_SECURE_EXECUTION_HEADER_CONTENT_BASE_64.replace("\n", ""),
                        TEST_ATTESTATION_PROTECTION_KEY_CONTENT_BASE_64.replace("\n", ""));
        assertTrue(result.succeeded());
        assertEquals(TEST_ATTESTATION_RESULT_YAML, result.attestationResultContent());
        assertEquals(TEST_RANDOM_USER_NONCE, result.randomUserNonceResultContent());
    }

    private void checkVerifyAttestationReportKO(PvattestWrapper pvaw)  {
        assertThrowsExactly(RhnRuntimeException.class,
                () -> pvaw.verifyAttestationReport(TEST_ATTESTATION_RESULT_CONTENT_BASE_64.replace("\n", ""),
                        TEST_SECURE_EXECUTION_HEADER_CONTENT_BASE_64.replace("\n", ""),
                        TEST_ATTESTATION_PROTECTION_KEY_CONTENT_BASE_64.replace("\n", "")),
                "error: Host-key verification failed: After validity period");
    }

    private void checkVerifyAttestationReportCommand(PvattestWrapper pvaw) {
        String command = pvaw.getLastExecutedCommand();

        assertTrue(command.startsWith("pvattest verify -v "));
        assertTrue(command.contains(" -i "));
        assertTrue(command.contains(" --hdr "));
        assertTrue(command.contains(" --arpk "));
        assertTrue(command.contains(" -o "));
        assertTrue(command.contains(" -u "));
    }

    @Test
    @Disabled("disabled: run only in local to test real PvattestWrapper (must have s390-tools installed)")
    public void testRealPvattestWrapper() throws ExecutionException, CertificateException {
        PvattestWrapper realPvattestWrapper = new PvattestWrapper();

        checkFindPackageVersion(realPvattestWrapper);
        checkVersion(realPvattestWrapper);

        checkCreateNoVerify(realPvattestWrapper);
        checkCreateNoVerifyCommand(realPvattestWrapper);

        checkCreateVerifyDownloadCertificatesKO(realPvattestWrapper);
        checkCreateVerifyDownloadCertificatesCommand(realPvattestWrapper);

        checkVerifyAttestationReportOK(realPvattestWrapper);
        checkVerifyAttestationReportCommand(realPvattestWrapper);
    }

    @Test
    @Disabled("disabled: run only in local to test certificates download")
    public void testDownloadingCertificates() throws IOException, CertificateEncodingException {
        X509Certificate digiCert = testPvattestWrapper.downloadDigiCertCACertificate();
        assertNotNull(digiCert);
        assertEquals(TEST_DIGI_CERT_CA_2036_04_29.replace("\n", ""),
                CertificateHelper.getPemCertificate(digiCert).replace("\n", ""));

        X509Certificate ibmCert = testPvattestWrapper.downloadIbmZHostKeySigningCertificate();
        assertNotNull(ibmCert);

        X509CRL ibmCrl = testPvattestWrapper.downloadIbmZHostKeySigningRevocationLists();
        assertNotNull(ibmCrl);
    }

    private static final String TEST_ATTESTATION_RESULT_CONTENT_BASE_64 = """
            cHZhdHRlc3QAAAEAAAACjgAAAAAAAAAAAAABkAAAAEAAAABAAAAB0AAAAEAAAAIQ
            AAAALgAAAlAAAAAQAAACfgAAAAAAAAAAAAABAAAAAZCz8o95xyTM/kw2NpEAAAAA
            AAAAAAAAAAEAAAAAAAAAUHAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAFv
            qBTUY6O9+2KbhNpR5fcQCQgucHom6tR9JYnm+ZAH/Wf6+ikMpFZbkdFbLZ1ghGzb
            vvZsb4PMznaJJlEaI+KP8gAAAAAAAAAAAAAAAAAAAAaISFizbu+oqU8lxJuPX+4b
            yOUxYM5nI+8D6UBZYncOqefx9bc9FQRbc8PFjs/BR4sADEmh29D1xSaTJhrEUjHk
            0fco79meHaZQ51hRJiGmX53Y132NNLHbu1aQTrNzuDyulCLYGJHPxM7XnSDNDjR9
            mIqNKn4b/9KtXp1yvZNtImaxOY/Y+cM2ECxVNK2c1/2/G7BpkNzfrnugTvIX/TTX
            HCHNOkwyl0iqpPI+r9dOKVa1McWfnOuGTGsVj7DRVwFeWELRTTAtS3Cr1TPHkTpE
            cdltCrKqPpyFPrJ/kL0ok+t7WSb+CbyWyQWTIZLcx3IIBMiN2p4+GOGFKHhjGmz5
            Nf3jEX2bmBeu8qmXt/8//x0avZGO0gc5UXx/+X7rwra3ZJkggHZl3pGRFpkGn8Bd
            0fco79meHaZQ51hRJiGmX53Y132NNLHbu1aQTrNzuDzR9yjv2Z4dplDnWFEmIaZf
            ndjXfY00sdu7VpBOs3O4PHJhbmRvbSB1c2VyIGRhdGEgZm9yIHN0YW5kYXJkX2F0
            dGVtcHRfNV8wM18xNgo+uRJTljTNzmYKuEAgkZDi""";

    private static final String TEST_SECURE_EXECUTION_HEADER_CONTENT_BASE_64 = """
            SUJNU2VjRXgAAAEAAAAEEImh0IohRiZOaGxFzwAAAAAAAAAAAAAABgAAAAAAAACA
            AAAAAAAAKOsAAAAAAAAA4AAAAAAAAAAAAAAAAAAAAaRRSkjSjX0Sssg7/TjS2I6/
            Mz0fVW/bM4Iu80Pe92tOFZ+ccVsOgW4UGmciyVShvDXtmnQf07gft7PMvdy/jF3w
            AAAAAAAAAAAAAAAAAAABE+dHHdCfTMG3aPxcNweaft0hNW4AJIrfRff0DYoq9tBb
            N46oVb/rhrfp/SNnrHhDt4/gx5AlI0qFIoADp58Rx0EkIZG29coRmo4Gbau5TZFu
            p7ZKv/M7KewIFAZE/rTPz8deqwTkHNeSWwLou8tXCHFSRkNYPXLQvV542JHvKYKE
            gtbbzKaAp0X/zL1OBjidrpEHw16Vxx82FgQH4WmbFDp+EOE6ss6l2vZbHvPXTk0s
            atkl0VgzYTl1KxvNXO4V5H0SNjhjXR1JRTHkWzfQqRIQSbIIIHrWOfMYib1jRaZo
            6eJg3Sq3vfp59xgfqzCW08SYiayqpbMpYMZz4wyC2JMm/h1D1rLvcASABUdCJ5R3
            InlJsomZ8VtRijRSsp45vYUS0BE9shi0o4mhA54C5J9R2vydyiY1hbaPGL8dDdxS
            Q6tFm7CDpZGIfj2/oO+CvdH3KO/Znh2mUOdYUSYhpl+d2Nd9jTSx27tWkE6zc7g8
            1G2RCgm+xOrovcqwgD4xEZLpVcSOYQSlAcQxxGzHkxFbxfi8g7grU5XGYUTu5Z9v
            zE+OYUBNroD/my/T4TIz9JHxL0T/Sw3vxGDcehSDpr8wJAJQzBr0cgfNg1Kiwe3I
            vy9PoegY+2UwJL5AXy6Pq3+4G7m4FeJeL7XjL6bX0SmvQ9fKJzOFLZUaVsleltol
            gSQVZ0nHnSKEg587i3Cp8jcN4b9xcJuOaPosu/uvrfmic2Dp7l3FcZJ8SGEou1o9
            W3W3f/w6foCWTVrP3oc97HkPPJgH/uMq6WPwBIh6YU00Yhi5AH/yzJUJ37hgFHu2
            5Y4/8eubCbauIO9Jo9MQ7PQWjhtO24//WJsh5rnTOn3AJr+OkEcPFN0ZSvWLJbLW
            7vjZJSAAmPuKomftGUgeWp8KG9X1HWx3FlGnaAFWFRKbFzE1p7mvEPlEFVAtPJ/9
            g3y3BFg4zuWZZnWCvSJ9r6ZOu9jZQw3sORmqvJbEg5bqFlXYioLtTKqfn4ppOqTM
            5SqsZ1jJHWorzcmOHgqVsXM09nfOFC06kX/OwqE4vb3w/3Lxms8n4XRHrsO7ODG5
            DoBdPldxmNRmiG+LAPdlUybbc6LjfNj0cy7Af8KT+izmhVp0bHKQg+tcHqngrAD5
            6zRwXzxfqQL7P14DdFhRmuI69PKkto+bnNMjfyY28q4=""";

    private static final String TEST_ATTESTATION_PROTECTION_KEY_CONTENT_BASE_64 =
            "fYRqcc4SCJvNItLR7IZtkoZY8N9Tz0uLhRXTwt4z45Q=";


    private static final String TEST_RANDOM_USER_NONCE = "random user data for standard_attempt_5_03_16\n";


    private static final String TEST_HUGE_STRING =
            "0xd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83" +
                    "cd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83c";

    private static final String TEST_ATTESTATION_RESULT_YAML =
        "cuid: '0x3eb912539634cdce660ab840209190e2'\n" +
        "add: " + TEST_HUGE_STRING + "\n" +
        "add_fields:\n" +
        "  image_phkh: 0xd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83c\n" +
        "  attestation_phkh: 0xd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83c\n" +
        "user_data: 0x72616e646f6d2075736572206461746120666f72207374616e646172645f617474656d70745f355f30335f31360a\n";

    private static final String TEST_ATTESTATION_REPORT_OUTPUT =
            "Attestation measurement verified\n" +
            "Config UID:\n" +
            "0x3eb912539634cdce660ab840209190e2\n" +
            "Additional-data:\n" +
            TEST_HUGE_STRING + "\n" +
            "Additional-data content:\n" +
            "Image PHKH\n" +
            "0xd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83c\n" +
            "Attestation PHKH\n" +
            "0xd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83c\n" +
            "user-data:\n" +
            "0x72616e646f6d2075736572206461746120666f72207374616e646172645f617474656d70745f355f30335f31360a\n";


    private static final String TEST_CERTIFICATE_2024_07_14 = """
            -----BEGIN CERTIFICATE-----
            MIIFRjCCAy6gAwIBAgIJZHtstznUcMSKMA0GCSqGSIb3DQEBDQUAMIHMMQswCQYD
            VQQGEwJVUzE0MDIGA1UECgwrSW50ZXJuYXRpb25hbCBCdXNpbmVzcyBNYWNoaW5l
            cyBDb3Jwb3JhdGlvbjEnMCUGA1UECwweSUJNIFogSG9zdCBLZXkgU2lnbmluZyBT
            ZXJ2aWNlMRUwEwYDVQQHDAxQb3VnaGtlZXBzaWUxETAPBgNVBAgMCE5ldyBZb3Jr
            MTQwMgYDVQQDDCtJbnRlcm5hdGlvbmFsIEJ1c2luZXNzIE1hY2hpbmVzIENvcnBv
            cmF0aW9uMB4XDTIyMDYxNTE3MjAxOVoXDTI0MDYxNDE3MjAxOVowgaoxCzAJBgNV
            BAYTAlVTMSgwJgYDVQQKDB9JbnRlcm5hdGlvbmFsIEJ1c2luZXNzIE1hY2hpbmVz
            MScwJQYDVQQLDB5JQk0gWiBIb3N0IEtleSBTaWduaW5nIFNlcnZpY2UxDzANBgNV
            BAcMBkFybW9uazERMA8GA1UECAwITmV3IFlvcmsxJDAiBgNVBAMMG2libS16LWhv
            c3Qta2V5LTAwMDAyMDA2ODhFODCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAOTg
            Qro26O3m61M9GftqU4ih1oJtt/WwnwIUhhJ0QIncJ47mxQc/Lcpc6SEC+Z9NRcak
            9DSjK5N8bL3SqGmK8qHkAYg7TaE345xsZlE0/HHKEaR5kt/n76j8Rh9OdF0Nuwfr
            tvhCnIbC6wWmv0fjHco1JOK3Hka1uBQKfLqSEtdUlLzpo4HSMIHPMA4GA1UdDwEB
            /wQEAwIDCDCBvAYDVR0fBIG0MIGxMHmgd6B1hnNodHRwczovL3d3dy5pYm0uY29t
            L3NlcnZlcnMvcmVzb3VyY2VsaW5rL2xpYjAzMDYwLm5zZi9wYWdlcy9JQk0tU2Vj
            dXJlLUV4ZWN1dGlvbi1mb3ItTGludXgvJGZpbGUvaWJtLXotaG9zdC1rZXkuY3Js
            MDSgMqAwhi5odHRwczovL2libS5iaXovaWJtLXotaG9zdC1rZXktcmV2b2NhdGlv
            bi1saXN0MA0GCSqGSIb3DQEBDQUAA4ICAQBMPAUPmopgtQpDaJjTtEoAJesvpNMk
            mzUfr7Rjk5PDk/X+oyUtkq5zDEGywMVyWjztRAoX+a1BvCEuoTbSF6f2H6veYwmd
            KauvxBZ/u50Ql+/YEDco56ZeFjeNzKpG1U3wPLSFjetExVrP2PfyqLqTT+nh3SNU
            qOMpWF1rXCJ/1Nvo4h7a7fFcbgpleNhPjXWO+oK5kex2RDbQs/Pq6hYBdRUwi99f
            ZlDUvs7NiYpgGaHM69slSxykgrJVEnQGz7FGuLAIgJ53r3E2Dxb2+JgzGqPTj+/z
            57HmuoiYr2XRJNGO0XQl/dJhDW4bqtH2enl2FYGiL7utFC2azWcNny74Xo0rd/4O
            m2SnZ78LOpjv1mysNogbimGZkBhAYldG1Wq0YGarFQkHPdSpcFTk7suWHeGiiQXa
            KSrHNCEhTmpK0wenXle15DuRo1HVXd1XUlXG8rvvvGjslMUv/fnBb3XAH47Q1JLB
            e7GoUdoqqtWYXZaQ1+AUlyvCq7+y6CVXOYi5AjQLO+QplyEaf8EXnQ08ilYPgL70
            YEBJuISLfYwfLxnuid7RLDYqON4J2lER2SDLRrcMAU5cCact6001wVBmxmC6bMjU
            AiiibBNzMaNHKQAdwwwahrgWXhcvpGhr3xpu0jwYlwpBkqfSEYn1hWTgvQIBllxZ
            SxGOjdKJdChuZw==
            -----END CERTIFICATE-----
            """;

    private static final String TEST_DIGI_CERT_CA_2036_04_29 = """
            -----BEGIN CERTIFICATE-----
            MIIGsDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBi
            MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
            d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3Qg
            RzQwHhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJV
            UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
            dXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIIC
            IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1
            M4zrPYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZ
            wZHMgQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI
            8IrgnQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGi
            TUyCEUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLm
            ysL0p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3S
            vUQakhCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tv
            k2E0XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+
            960IHnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3s
            MJN2FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FK
            PkBHX8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1H
            s/q27IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAw
            HQYDVR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LS
            cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
            BQcDAzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
            Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
            Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
            aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
            cmwwHAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQAD
            ggIBADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L
            /Z6jfCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHV
            UHmImoqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rd
            KOtfJqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK
            6Wrxoj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43N
            b3Y3LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4Z
            XDlx4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvm
            oLr9Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8
            y4+ICw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMM
            B0ug0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+F
            SCH5Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhO
            -----END CERTIFICATE-----
            """;
}
