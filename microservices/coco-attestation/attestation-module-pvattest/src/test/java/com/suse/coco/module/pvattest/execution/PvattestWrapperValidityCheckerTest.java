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

package com.suse.coco.module.pvattest.execution;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.suse.coco.module.pvattest.PvattestTestHelper;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

public class PvattestWrapperValidityCheckerTest {

    public static final String TEST_DUMMY_CERT_BODY_FROM_2000_TO_2068 = """
            MIIDbTCCAlWgAwIBAgIICN6hcheezRowDQYJKoZIhvcNAQELBQAwgYoxCzAJBgNV
            BAYTAkNOMRMwEQYDVQQDDApleGFtcGxlLmNuMRAwDgYDVQQKDAdDb21wYW55MREw
            DwYDVQQLDAhEaXZpc2lvbjEOMAwGA1UECAwFQW5IdWkxDjAMBgNVBAcMBUhlRmVp
            MSEwHwYJKoZIhvcNAQkBFhJleGFtcGxlQGV4YW1wbGUuY24wIBcNMDAwNDIzMTk1
            MDQzWhgPMjA2ODA0MjMxOTUwNDNaMGAxCzAJBgNVBAYTAkNOMRQwEgYDVQQDDAtl
            eGFtcGxlLm9yZzEJMAcGA1UECgwAMQkwBwYDVQQLDAAxCTAHBgNVBAgMADEJMAcG
            A1UEBwwAMQ8wDQYJKoZIhvcNAQkBFgAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
            ggEKAoIBAQCAczqN9F8GGPgGAasVLgQEAIak6Cwi2rj4VzSC8hh2k8jt2fmBu72X
            eidb2SsvNyddh40LBzHntIfoxUvkOliJW6nTvU/lw2ZJYWnTDEWN5so3mG5X2DRb
            E0jpqFcenp7VS8xxsTw/+gXSpFNF+hFRRqP0tjSZYxqkw70nlU1uFmY9CvmR74RH
            a0nSJ4SojDeub4yYD5G8kQT7oYi4TBPbQvmVJkoH+0gejfAroRGryBfqzz4GajQy
            D7wxvjutgFCQgJdDPJW0g3nwLq3trTOoSj1e3lKAYWPs6h0BhCewzQv07I96ur8/
            qvwgK+NHDaySaohWV9CtsfRtmTRWe1BTAgMBAAEwDQYJKoZIhvcNAQELBQADggEB
            AG8t8/G3Dc69emEtIYQd1DoJ6ep3ldnsdkrXfm3AN2kCPRfZlaptyQCARHhibn5F
            OqJyDkKM/2fiFOkxY4zzv6rJBzD7s+cWZHXKmTVb36u61ZAwHqtDH5RrFqPIq1Dy
            K5av+vklKeyAJFbTFr/alwB6vp3rVWzBsYnJACm/IXZaQQZKf+QUvYjvmKTGiqVY
            f7FlLTtFclcVduBnkMv2lQWQZu6UcTpuI65lgUypWCWAXA1zqs4h2de0oKd01jnH
            7ZvFF9HNFFbiytOSzWHpdCjO8WvGVdCWGHHHaLcYBNjsUmeJEZlLAAdM1TfizPGN
            ZSnWVW4JqcLzngpjyb8KXcc=""";

    public static final String TEST_DUMMY_CERT_BODY_FROM_2067_TO_2068 = """
            MIIDbzCCAlegAwIBAgIICN6hcnR5MYIwDQYJKoZIhvcNAQELBQAwgYoxCzAJBgNV
            BAYTAkNOMRMwEQYDVQQDDApleGFtcGxlLmNuMRAwDgYDVQQKDAdDb21wYW55MREw
            DwYDVQQLDAhEaXZpc2lvbjEOMAwGA1UECAwFQW5IdWkxDjAMBgNVBAcMBUhlRmVp
            MSEwHwYJKoZIhvcNAQkBFhJleGFtcGxlQGV4YW1wbGUuY24wIhgPMjA2NzA0MjMx
            OTUwNDNaGA8yMDY4MDQyMzE5NTA0M1owYDELMAkGA1UEBhMCQ04xFDASBgNVBAMM
            C2V4YW1wbGUub3JnMQkwBwYDVQQKDAAxCTAHBgNVBAsMADEJMAcGA1UECAwAMQkw
            BwYDVQQHDAAxDzANBgkqhkiG9w0BCQEWADCCASIwDQYJKoZIhvcNAQEBBQADggEP
            ADCCAQoCggEBAK47iQ3HudAwtwDgr0JeuYnSlTl5JEaH5VUBo1QM7Us1veYH4qwu
            bPbfHh9YPwV1+RII9F8YboeL8LjgoWovdri8qX+J5KtNchX8KsvCTNG4zGojO6A2
            uFnb7Ta0YqUe6Sb30whr0nRvnHS6H7SVW0jXMjbzVv2bVsmB93/j6bH5fGfSN1i6
            g0tdQ+inJ10CO5pSGa+AmGAKmyDK9Hm2iEQG3e5eWqLazID42vJ0nDIccGWeEg1G
            L6eCiXC84uAKYbYbrxqFmy/86iqEUMXZ2mo3CGV1OPZVuQHUhcBBHyvreTshzJmw
            jIe8fzVOKJ7yry+RQ5XtMwCGS7PpkryXJBECAwEAATANBgkqhkiG9w0BAQsFAAOC
            AQEAIQUuUzf335WOz52REy91U7WjVvk418P2VaeteJiWWy92MglRZ5UeDcoAwaQG
            r34roPpCyeW6elX/4Q+4FNyXsc8+GhZ4XWkXsXPzCDE764Tk+1LStiOaxb9x8uQu
            jMNtYKzK8NHz1Ema/DV0jaAYi/lzDjQaav2zqG+dK20OPz5TWfsIheMp5bHWJ9AL
            L9PlS2pgsQmKMpqNJ8zxzS7cudtGBlB2rpgNVYy0GtAc4U4SlwFkhDvj2RXVJZTC
            eCYLQBkby4ZF1i7fV4aHd/+5BPr/SQk2E239ApkJbY5QeCX/VDNO2X1D4uoQLo9a
            eyEEQYLpP3C9C6oppsJ9tqzByw==
            """;

    public static final String TEST_DUMMY_CERT_BODY_FROM_2000_TO_2001 = """
            MIIDazCCAlOgAwIBAgIICN6hcrZ0z58wDQYJKoZIhvcNAQELBQAwgYoxCzAJBgNV
            BAYTAkNOMRMwEQYDVQQDDApleGFtcGxlLmNuMRAwDgYDVQQKDAdDb21wYW55MREw
            DwYDVQQLDAhEaXZpc2lvbjEOMAwGA1UECAwFQW5IdWkxDjAMBgNVBAcMBUhlRmVp
            MSEwHwYJKoZIhvcNAQkBFhJleGFtcGxlQGV4YW1wbGUuY24wHhcNMDAwNDIzMTk1
            MDQzWhcNMDEwNDIzMTk1MDQzWjBgMQswCQYDVQQGEwJDTjEUMBIGA1UEAwwLZXhh
            bXBsZS5vcmcxCTAHBgNVBAoMADEJMAcGA1UECwwAMQkwBwYDVQQIDAAxCTAHBgNV
            BAcMADEPMA0GCSqGSIb3DQEJARYAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
            CgKCAQEA4EwlSPe+JD5ZoN5O+GE+JkNLctM3UqZRyM+XRsH//VID0iBwk4AGvnB8
            D8aeqp8x6OOR2q1wEkFzh4R6ox1TFY1v8e7iRU1BMmNh/vFY8BRUgP5yVbtBf6ol
            vhXBYCItCAv3wVk1hulWPxGG8svigmPbOHZetUw03DlmUGoOUFnZMV6z7rlyOJ/4
            AUx0KnXanR42maS79OTDJXgSQ5JgobqcZXt/n6IpVgYV03UaD7D++feO6rzS3Uii
            +ct5q0ONEhj+IsSFlStysGq6AdINOzfDWGf7EjRSyizxFEoZYZAT9qvSI/hIiozh
            fcGY6pSLvbsHJ8TNIu6jgcARfsp+0QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQDa
            fnRxn5Y1f7EQ86oPBLBct/XW3JfZRJZdDrzsV4jyK5XSQPU3K3HwUqq4IYbtPJiF
            IbzVzJuUSYYhdB5Z3FFyhhoI6o//GHLGA5nibYDipxvtH4eQVoe6Qmcyv1ZEJJao
            mTahRcHHyUbOmqb0x7jOYh0DxoeCFqoDEL5+n7gX+17gcxafXNsCG/JMFKK3ydZj
            YFZmWvXMlPqfL0DvTkMjmquGeVejt73QgBH1IH9YMvvo/KWOXZd47JAdR/u+ciZn
            CKszzwRUHPVk8hXhskN/RslnnMS0Ws+dA4Lx8L1r/4+/cZF2ekqXECZH6TPdtXp8
            Jh7nF4dmH/B9Zt9EFIDi
            """;

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----\n";
    public static final String END_CERT = "\n-----END CERTIFICATE-----";

    private final PvattestWrapperValidityChecker testValidityChecker = new PvattestWrapperValidityChecker();

    @Test
    @DisplayName("test validity of valid host key documents")
    public void testCheckValidHostKeyDocument() {
        assertTrue(testValidityChecker.isValidHostKeyDocument(PvattestTestHelper.HOST_KEY_DOCUMENT));
        assertEquals("", testValidityChecker.getValidityError());
        assertEquals("", testValidityChecker.getLogValidityError());

        assertTrue(testValidityChecker.isValidHostKeyDocument(
                BEGIN_CERT + TEST_DUMMY_CERT_BODY_FROM_2000_TO_2068 + END_CERT));
        assertEquals("", testValidityChecker.getValidityError());
        assertEquals("", testValidityChecker.getLogValidityError());
    }

    @Test
    @DisplayName("test validity of invalid host key documents caused by wrong certificate header and footer")
    public void testCheckInvalidHostKeyDocumentHeaderFooter() {

        //missing dashes before BEGIN CERTIFICATE
        assertFalse(testValidityChecker.isValidHostKeyDocument(
                "---BEGIN CERTIFICATE-----\n" +
                        TEST_DUMMY_CERT_BODY_FROM_2000_TO_2068 + END_CERT));
        assertEquals("Incomplete data", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //typo BEIN
        assertFalse(testValidityChecker.isValidHostKeyDocument(
                "-----BEIN CERTIFICATE-----\n" +
                        TEST_DUMMY_CERT_BODY_FROM_2000_TO_2068 + END_CERT));
        assertEquals("Illegal header: -----BEIN CERTIFICATE-----", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //missing dashes after BEGIN CERTIFICATE
        assertFalse(testValidityChecker.isValidHostKeyDocument(
                "-----BEGIN CERTIFICATE--\n" +
                        TEST_DUMMY_CERT_BODY_FROM_2000_TO_2068 + END_CERT));
        assertEquals("Illegal header: -----BEGIN CERTIFICATE--", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //missing \n after BEGIN CERTIFICATE
        assertFalse(testValidityChecker.isValidHostKeyDocument(
                "-----BEGIN CERTIFICATE-----" +
                        TEST_DUMMY_CERT_BODY_FROM_2000_TO_2068 + END_CERT));
        assertTrue(testValidityChecker.getValidityError().startsWith("Illegal header: -----BEGIN CERTIFICATE-----"));
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //missing dashes before END CERTIFICATE
        assertFalse(testValidityChecker.isValidHostKeyDocument(
                BEGIN_CERT + TEST_DUMMY_CERT_BODY_FROM_2000_TO_2068 +
                        "----END CERTIFICATE-----"));
        assertEquals("Illegal footer: ----END CERTIFICATE-----", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //typo EMD
        assertFalse(testValidityChecker.isValidHostKeyDocument(
                BEGIN_CERT + TEST_DUMMY_CERT_BODY_FROM_2000_TO_2068 +
                        "-----EMD CERTIFICATE-----"));
        assertEquals("Illegal footer: -----EMD CERTIFICATE-----", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));


        //missing dashes after END CERTIFICATE
        assertFalse(testValidityChecker.isValidHostKeyDocument(
                BEGIN_CERT + TEST_DUMMY_CERT_BODY_FROM_2000_TO_2068 +
                        "-----END CERTIFICATE---"));
        assertEquals("Illegal footer: -----END CERTIFICATE---", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //not matching
        assertFalse(testValidityChecker.isValidHostKeyDocument(
                "-----BEGIN THIS-----\n" +
                        TEST_DUMMY_CERT_BODY_FROM_2000_TO_2068 +
                        "\n-----END THAT-----"));
        assertEquals("Header and footer do not match: -----BEGIN THIS----- -----END THAT-----",
                testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));
    }

    private String modifyDummyCertBody(int pos, char content) {
        char[] certBody = TEST_DUMMY_CERT_BODY_FROM_2000_TO_2068.toCharArray();
        certBody[pos] = content;
        return String.valueOf(certBody);
    }

    @Test
    @DisplayName("test validity of invalid host key documents caused by invalid content")
    public void testCheckInvalidHostKeyDocumentContent() {

        //gibberish content
        assertFalse(testValidityChecker.isValidHostKeyDocument(BEGIN_CERT +
                "gibberish7358358309487530475089374509374583745037503" + END_CERT));
        assertEquals("not enough content", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //casual content injection
        assertFalse(testValidityChecker.isValidHostKeyDocument(BEGIN_CERT +
                modifyDummyCertBody(14, 'z') + END_CERT));
        assertEquals("Invalid lenByte", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //casual content injection
        assertFalse(testValidityChecker.isValidHostKeyDocument(BEGIN_CERT +
                modifyDummyCertBody(47, 'z') + END_CERT));
        assertEquals("Signature algorithm mismatch", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //invalid base64 char injection
        assertFalse(testValidityChecker.isValidHostKeyDocument(BEGIN_CERT +
                modifyDummyCertBody(145, '{') + END_CERT));
        assertEquals("java.lang.IllegalArgumentException: Illegal base64 character 7b",
                testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));
    }

    @Test
    @DisplayName("test validity of invalid host key documents caused by time invalidity")
    public void testCheckInvalidHostKeyDocumentTimeValidity() {

        //not yet valid certificate
        assertFalse(testValidityChecker.isValidHostKeyDocument(BEGIN_CERT +
                TEST_DUMMY_CERT_BODY_FROM_2067_TO_2068 +
                END_CERT));
        assertTrue(testValidityChecker.getValidityError()
                .startsWith("Certificate not yet valid: NotBefore: Sat Apr 23"));
        assertTrue(testValidityChecker.getValidityError().endsWith("2067"));
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //expired certificate
        assertFalse(testValidityChecker.isValidHostKeyDocument(BEGIN_CERT +
                TEST_DUMMY_CERT_BODY_FROM_2000_TO_2001 +
                END_CERT));
        assertTrue(testValidityChecker.getValidityError()
                .startsWith("Certificate expired: NotAfter: Mon Apr 23"));
        assertTrue(testValidityChecker.getValidityError().endsWith("2001"));
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));
    }


    @Test
    @DisplayName("test validity of valid secure execution header")
    public void testCheckValidSecureExecutionHeader() {
        assertTrue(testValidityChecker.isValidSecureExecutionHeader(PvattestTestHelper.SEH));
        assertEquals("", testValidityChecker.getValidityError());
        assertEquals("", testValidityChecker.getLogValidityError());

        // string "IBMSecEx0123456789abcdefghijklmnopq"
        assertTrue(testValidityChecker.isValidSecureExecutionHeader(
                "SUJNU2VjRXgwMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHEK"));
        assertEquals("", testValidityChecker.getValidityError());
        assertEquals("", testValidityChecker.getLogValidityError());
    }

    private String modifySeh(int pos, byte content) {
        byte[] seh = Base64.getDecoder().decode(PvattestTestHelper.SEH.replace("\n", ""));
        seh[pos] = content;
        return Base64.getEncoder().encodeToString(seh);
    }

    @Test
    @DisplayName("test validity of invalid secure execution header")
    public void testCheckInValidSecureExecutionHeader() {

        //empty
        assertFalse(testValidityChecker.isValidSecureExecutionHeader(""));
        assertEquals("empty", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //empty
        assertFalse(testValidityChecker.isValidSecureExecutionHeader("123{5"));
        assertEquals("Illegal base64 character 7b", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        // string "1234567"
        assertFalse(testValidityChecker.isValidSecureExecutionHeader("MTIzNDU2Nwo="));
        assertEquals("too short", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        // string "12345678"
        assertFalse(testValidityChecker.isValidSecureExecutionHeader("MTIzNDU2NzgK"));
        assertEquals("invalid header", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        // string "IBM Sec Ex"
        assertFalse(testValidityChecker.isValidSecureExecutionHeader("SUJNIFNlYyBFeAo"));
        assertEquals("invalid header", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        //casual content injection in header bytes
        assertFalse(testValidityChecker.isValidSecureExecutionHeader(modifySeh(0, (byte) 0x0A)));
        assertEquals("invalid header", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));

        assertFalse(testValidityChecker.isValidSecureExecutionHeader(modifySeh(7, (byte) 0x0A)));
        assertEquals("invalid header", testValidityChecker.getValidityError());
        assertTrue(testValidityChecker.getLogValidityError().contains(testValidityChecker.getValidityError()));
    }
}
