/*
 * Copyright (c) 2025 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 */
package com.suse.coco.module.pvattest;

public class PvattestTestHelper {

    private PvattestTestHelper() {
        // utility classes should not have a public or default constructor
    }

    public static final String HOST_KEY_DOCUMENT = """
            -----BEGIN CERTIFICATE-----
            MIIE9TCCAt2gAwIBAgIJe8PccaVpNh0HMA0GCSqGSIb3DQEBDQUAMIHOMQswCQYD
            VQQGEwJVUzE0MDIGA1UECgwrSW50ZXJuYXRpb25hbCBCdXNpbmVzcyBNYWNoaW5l
            cyBDb3Jwb3JhdGlvbjEpMCcGA1UECwwgSUJNIFoxNiBIb3N0IEtleSBTaWduaW5n
            IFNlcnZpY2UxFTATBgNVBAcMDFBvdWdoa2VlcHNpZTERMA8GA1UECAwITmV3IFlv
            cmsxNDAyBgNVBAMMK0ludGVybmF0aW9uYWwgQnVzaW5lc3MgTWFjaGluZXMgQ29y
            cG9yYXRpb24wHhcNMjUwNzI0MTI1ODAxWhcNMjcwNzE0MTI1ODAxWjCBsjELMAkG
            A1UEBhMCVVMxKDAmBgNVBAoMH0ludGVybmF0aW9uYWwgQnVzaW5lc3MgTWFjaGlu
            ZXMxKzApBgNVBAsMIklCTSBaIEhvc3QgS2V5IFNpZ25pbmcgU2VydmljZSB6MTYx
            DzANBgNVBAcMBkFybW9uazERMA8GA1UECAwITmV3IFlvcmsxKDAmBgNVBAMMH2li
            bS16LWhvc3Qta2V5LXoxNi0wMDAwMjAwOTY3RjgwgZswEAYHKoZIzj0CAQYFK4EE
            ACMDgYYABAF2VvGprND7keEiJiJcxd5RIm0ESri3ellnO2/dS+WwylmDRvmdCWUu
            3ybnKRq4KFzGhKj518M9hstng2ja5h27bQAuwihmhmNuHhmFKUii6DwKU99nE5uO
            M8FlKoqPGNvtcaVCdlR6i7NOTRlRhOMvMKrI6Gd6NwCs/iPA8APgM0VVA6N4MHYw
            DgYDVR0PAQH/BAQDAgMIMGQGA1UdHwRdMFswWaBXoFWGU2h0dHBzOi8vd3d3Lmli
            bS5jb20vc3VwcG9ydC9yZXNvdXJjZWxpbmsvYXBpL2NvbnRlbnQvcHVibGljL2li
            bS16LWhvc3Qta2V5LWdlbjIuY3JsMA0GCSqGSIb3DQEBDQUAA4ICAQCYPt5K047O
            dfoUXF7Qbsm9LiS8mwOinU7VcuD7yYJD8FSI9ghocfN7Amm+y9UgaqC+51qRvNBQ
            RzFt08GYASXcoAYf5FzS6MPogKOfK0jWVsGW81l3YuY5II+kUWu3kAwABz/jAXhp
            tRVByux1dwkQ0CFVfUgkQiYi4of7oWTIk2qmRh3Ho2Pbh21FcErFpQGt0HaWyYFK
            ntRaMJWXdIVyWBXfmDfeyjfDPcIMHJRjWKgSuepAOLY6hrmnFuDc+uty85n1g5eI
            ZlFe6Uyql0FdqB/cRAD9aQn2of8JEgofiEdSzZtPAJLN0l6CEjBVJlsJZeJvRhxv
            JFpYKJjtNMK3NJrh7Xy1x7xYZwK3l03wLWKUZL41BzTGCorr5NOOdrSGv6MHyBhr
            5UKqSTLY6qqzsRMNLcU5W83+crUIDNnO1GA4n4Cdl/HdFZND8bcIuwZGWRi6f+dW
            Z+8nPp2o/uhghscyUIPbyzXoC5mUjauAZUvXozopwrLMNY0fVLDDKo7QqTftEgTA
            sM3cxhERESvauVdzF1O2wzLUi508q0zGZGzK8tR0EMjhhVZNBSt4hduP3e/vWGi+
            NWxXvtoYScvLaQidA5W7Va0S7MeS2/oZgBPQqsPzBPh/cuRnEuFrLNbuZwvSjnGO
            57VBzkLzXz7yqpcwz35dBnjy/xIIxoCIkw==
            -----END CERTIFICATE-----""";

    public static final String TEST_RANDOM_USER_NONCE = "random user data for standard_attempt_5_03_16\n";

    public static final String TEST_RANDOM_USER_NONCE_BASE64 =
            "cmFuZG9tIHVzZXIgZGF0YSBmb3Igc3RhbmRhcmRfYXR0ZW1wdF81XzAzXzE2Cg==";

    public static final String TEST_ATTESTATION_REQUEST_CONTENT_BASE_64 = """
            cHZhdHRlc3QAAAEAAAAB0AAAAAAAAAAAAAABkAAAAEAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAABAAAAAZAVPjcwo37YUMD9eEwAAAAAAAAAAAAAAAEAAAAAAAAAUHAA
            AAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAD8v4H1zkoiJuJ1RKyBubm5N/HEARmO9dnXWMQi
            lIf8Q0jzmhBoQ1qwtg1yFViLjAdewR//XKl2oaw+2ofVMyQ91QAAAAAAAAAAAAAAAAAAAF0sBRfj
            ctmB5lED9rVuytdmBbxfTZocRRX5EFE1vtYnxy7qRFvMNDtPhBF0e0+6RHl+L4LTgBRMwVHLNFFJ
            gUi00fco79meHaZQ51hRJiGmX53Y132NNLHbu1aQTrNzuDyX2zPIPaNmgzT+xXP3xWGnyS75+Eum
            Ue4xEr5cE6VA23ESbhiMYP9+izym6UhXIDAoLreH30EUL+q3223dAS9fQUsn7wWQK5WXAdK7qoQz
            E5eVBy4u9/mO4vAIWtwJfhXMAcw8Nh4maUdN912UT4puMRHph3coteViR0cAGyaFhftun93pyCS/
            gkkAPvYhHOM=""";


    public static final String TEST_ATTESTATION_PROTECTION_KEY_CONTENT_BASE_64 =
            "eGbGejX2F11UghHcvw0zbRUGXP7/K89ZrBKthSslqn8=";


    //please keep it as a string concatenation, to avoid \n problems
    public static final String SEH =
            "SUJNU2VjRXgAAAEAAAAEEImh0IohRiZOaGxFzwAAAAAAAAAAAAAABgAAAAAAAACAAAAAAAAAKOsA" +
                    "AAAAAAAA4AAAAAAAAAAAAAAAAAAAAaRRSkjSjX0Sssg7/TjS2I6/Mz0fVW/bM4Iu80Pe92tOFZ+c" +
                    "cVsOgW4UGmciyVShvDXtmnQf07gft7PMvdy/jF3wAAAAAAAAAAAAAAAAAAABE+dHHdCfTMG3aPxc" +
                    "Nweaft0hNW4AJIrfRff0DYoq9tBbN46oVb/rhrfp/SNnrHhDt4/gx5AlI0qFIoADp58Rx0EkIZG2" +
                    "9coRmo4Gbau5TZFup7ZKv/M7KewIFAZE/rTPz8deqwTkHNeSWwLou8tXCHFSRkNYPXLQvV542JHv" +
                    "KYKEgtbbzKaAp0X/zL1OBjidrpEHw16Vxx82FgQH4WmbFDp+EOE6ss6l2vZbHvPXTk0satkl0Vgz" +
                    "YTl1KxvNXO4V5H0SNjhjXR1JRTHkWzfQqRIQSbIIIHrWOfMYib1jRaZo6eJg3Sq3vfp59xgfqzCW" +
                    "08SYiayqpbMpYMZz4wyC2JMm/h1D1rLvcASABUdCJ5R3InlJsomZ8VtRijRSsp45vYUS0BE9shi0" +
                    "o4mhA54C5J9R2vydyiY1hbaPGL8dDdxSQ6tFm7CDpZGIfj2/oO+CvdH3KO/Znh2mUOdYUSYhpl+d" +
                    "2Nd9jTSx27tWkE6zc7g81G2RCgm+xOrovcqwgD4xEZLpVcSOYQSlAcQxxGzHkxFbxfi8g7grU5XG" +
                    "YUTu5Z9vzE+OYUBNroD/my/T4TIz9JHxL0T/Sw3vxGDcehSDpr8wJAJQzBr0cgfNg1Kiwe3Ivy9P" +
                    "oegY+2UwJL5AXy6Pq3+4G7m4FeJeL7XjL6bX0SmvQ9fKJzOFLZUaVsleltolgSQVZ0nHnSKEg587" +
                    "i3Cp8jcN4b9xcJuOaPosu/uvrfmic2Dp7l3FcZJ8SGEou1o9W3W3f/w6foCWTVrP3oc97HkPPJgH" +
                    "/uMq6WPwBIh6YU00Yhi5AH/yzJUJ37hgFHu25Y4/8eubCbauIO9Jo9MQ7PQWjhtO24//WJsh5rnT" +
                    "On3AJr+OkEcPFN0ZSvWLJbLW7vjZJSAAmPuKomftGUgeWp8KG9X1HWx3FlGnaAFWFRKbFzE1p7mv" +
                    "EPlEFVAtPJ/9g3y3BFg4zuWZZnWCvSJ9r6ZOu9jZQw3sORmqvJbEg5bqFlXYioLtTKqfn4ppOqTM" +
                    "5SqsZ1jJHWorzcmOHgqVsXM09nfOFC06kX/OwqE4vb3w/3Lxms8n4XRHrsO7ODG5DoBdPldxmNRm" +
                    "iG+LAPdlUybbc6LjfNj0cy7Af8KT+izmhVp0bHKQg+tcHqngrAD56zRwXzxfqQL7P14DdFhRmuI6" +
                    "9PKkto+bnNMjfyY28q4=";


    public static final String TEST_SECURE_EXECUTION_HEADER_CONTENT_BASE_64 = """
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

    public static final String TEST_ATTESTATION_RESPONSE_CONTENT_BASE_64 = """
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


    public static final String TEST_HUGE_STRING =
            "0xd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83" +
                    "cd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83c";

    //suppress checkstyle warnings in order to keep it as it appears in the file
    @SuppressWarnings("checkstyle:lineLength")
    public static final String TEST_ATTESTATION_RESULT_YAML =
            "cuid: '0x3eb912539634cdce660ab840209190e2'\n" +
                    "add: " + TEST_HUGE_STRING + "\n" +
                    "add_fields:\n" +
                    "  image_phkh: 0xd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83c\n" +
                    "  attestation_phkh: 0xd1f728efd99e1da650e758512621a65f9dd8d77d8d34b1dbbb56904eb373b83c\n" +
                    "user_data: 0x72616e646f6d2075736572206461746120666f72207374616e646172645f617474656d70745f355f30335f31360a\n";

    public static final String TEST_ATTESTATION_RESULT_OUTPUT =
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


    public static final String TEST_CERTIFICATE_2024_07_14 = """
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

    public static final String TEST_DIGI_CERT_CA_2036_04_29 = """
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

    public static String getOutData() {
        return getOutData(PvattestTestHelper.TEST_ATTESTATION_RESPONSE_CONTENT_BASE_64);
    }

    public static String getOutData(String attResponse) {
        StringBuilder builder = new StringBuilder();
        builder.append("{");

        if (null != attResponse) {
            builder.append("\"attestation_response\": ");
            builder.append("\"");
            builder.append(attResponse);
            builder.append("\"");
        }

        builder.append("}");
        return builder.toString();
    }

    public static String getInputData() {
        return getInputData(PvattestTestHelper.TEST_RANDOM_USER_NONCE,
                PvattestTestHelper.TEST_ATTESTATION_RESPONSE_CONTENT_BASE_64,
                PvattestTestHelper.TEST_ATTESTATION_PROTECTION_KEY_CONTENT_BASE_64);
    }

    public static String getInputData(String nonce, String attRequest, String attKey) {
        String separator = "";
        StringBuilder builder = new StringBuilder();
        builder.append("{");

        if (null != nonce) {
            builder.append(separator);
            builder.append("\"nonce\": ");
            builder.append("\"");
            builder.append(nonce);
            builder.append("\"");
            separator = ", ";
        }

        if (null != attRequest) {
            builder.append(separator);
            builder.append("\"attestation_request\": ");
            builder.append("\"");
            builder.append(attRequest);
            builder.append("\"");
            separator = ", ";
        }

        if (null != attKey) {
            builder.append(separator);
            builder.append("\"attestation_protection_key\": ");
            builder.append("\"");
            builder.append(attKey);
            builder.append("\"");
        }

        builder.append("}");
        return builder.toString();
    }

    public static String getConfigData() {
        return getConfigData(PvattestTestHelper.HOST_KEY_DOCUMENT,
                PvattestTestHelper.SEH);
    }

    public static String getConfigData(String hostKeyDocument, String secureExecutionHeader) {
        String separator = "";
        StringBuilder builder = new StringBuilder();
        builder.append("{");

        if (null != hostKeyDocument) {
            builder.append(separator);
            builder.append("\"host_key_document\": ");
            builder.append("\"");
            builder.append(hostKeyDocument);
            builder.append("\"");
            separator = ", ";
        }

        if (null != secureExecutionHeader) {
            builder.append(separator);
            builder.append("\"secure_execution_header\": ");
            builder.append("\"");
            builder.append(secureExecutionHeader);
            builder.append("\"");
        }

        builder.append("}");
        return builder.toString();
    }

}
