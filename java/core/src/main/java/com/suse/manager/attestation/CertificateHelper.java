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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CertificateHelper {
    private static final Logger LOGGER = LogManager.getLogger(CertificateHelper.class);

    private static final String PEM_BEGIN_CERT_TAG = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_END_CERT_TAG = "-----END CERTIFICATE-----";

    private CertificateHelper() {
        // Prevent instantiation
    }

    /**
     * @param certificateUrl dummy
     * @return dummy
     * @throws IOException dummy
     */
    public static X509Certificate downloadCertificate(String certificateUrl) throws IOException {
        try {
            return CertificateHelper.parse(downloadStringContent(certificateUrl));
        }
        catch (CertificateException ex) {
            String errorString = "Unable to parse certificate: {%s} {%s}".formatted(certificateUrl, ex.getMessage());
            throw new IOException(errorString);
        }
    }

    /**
    * @param pemCertificate  dummy
    * @return  dummy
    * @throws CertificateException  dummy
    */
    public static X509Certificate parse(String pemCertificate) throws CertificateException {
        if (pemCertificate == null || pemCertificate.isEmpty()) {
            throw new CertificateException("empty or null PEM certificate");
        }

        try (InputStream inputStream = new ByteArrayInputStream(pemCertificate.getBytes(StandardCharsets.UTF_8))) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        }
        catch (IOException ex) {
            throw new CertificateParsingException("Unable to load certificate from byte array", ex);
        }
    }

    /**
     * @param crlUrl dummy
     * @return dummy
     * @throws IOException dummy
     */
    public static X509CRL downloadCertificateRevocationList(String crlUrl) throws IOException {
        try {
            return CertificateHelper.parseCertificateRevocationList(downloadStringContent(crlUrl));
        }
        catch (CertificateException ex) {
            String errorString = "Unable to parse certificate: {%s} {%s}".formatted(crlUrl, ex.getMessage());
            throw new IOException(errorString);
        }
    }

    /**
     * @param pemCrlCertificate  dummy
     * @return  dummy
     * @throws CertificateException  dummy
     */
    public static X509CRL parseCertificateRevocationList(String pemCrlCertificate) throws CertificateException {
        return CertificateHelper.parseCrl(pemCrlCertificate);
    }

    /**
     * @param urlIn dummy
     * @return dummy
     * @throws IOException dummy
     */
    private static String downloadStringContent(String urlIn) throws IOException {
        try (BufferedInputStream in = new BufferedInputStream(new URL(urlIn).openStream())) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * @param cert  dummy
     * @return  dummy
     * @throws CertificateEncodingException  dummy
     */
    public static String getPemCertificate(X509Certificate cert) throws CertificateEncodingException {

        StringBuilder sb = new StringBuilder();
        sb.append(PEM_BEGIN_CERT_TAG);
        sb.append("\n");
        sb.append(Base64.getEncoder().encodeToString(cert.getEncoded()));
        sb.append("\n");
        sb.append(PEM_END_CERT_TAG);

        return sb.toString();
    }



    /**
     * Parse the given certificate revocation list
     * @param pemCrlCertificate a string representing the PEM certificate. Might be empty or null
     * @return the certificate
     * @throws CertificateException when an error occurs while parsing the data
     */
    public static X509CRL parseCrl(String pemCrlCertificate) throws CertificateException {
        if (pemCrlCertificate == null || pemCrlCertificate.isEmpty()) {
            throw new CertificateException("empty or null PEM CRL certificate");
        }

        try (InputStream inputStream = new ByteArrayInputStream(pemCrlCertificate.getBytes(StandardCharsets.UTF_8))) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509CRL)certificateFactory.generateCRL(inputStream);
        }
        catch (IOException | CRLException ex) {
            throw new CertificateParsingException("Unable to load certificate from byte array", ex);
        }
    }


}
