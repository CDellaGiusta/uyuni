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

import com.redhat.rhn.common.util.http.HttpClientAdapter;

import com.suse.utils.CertificateUtils;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.NoRouteToHostException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;

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
        Optional<Certificate> cert = CertificateUtils.parse(pemCertificate);
        return (X509Certificate) cert.orElseThrow();
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
        //Optional<Certificate> cert = CertificateUtils.parse(pemCrlCertificate);
        Optional<X509CRL> crl = CertificateHelper.parseCrl(pemCrlCertificate);
        return crl.orElseThrow();
    }


    /**
     * @param urlIn dummy
     * @return dummy
     * @throws IOException dummy
     */
    private static String downloadStringContent(String urlIn) throws IOException {

        URI certificateURI = null;
        try {
            certificateURI = new URI(urlIn);
        }
        catch (URISyntaxException ex) {
            LOGGER.error("Unable to get content from url: {} {}.", urlIn, ex.getMessage());
        }

        HttpClientAdapter httpClient = new HttpClientAdapter(null, false);

        HttpRequestBase request = new HttpGet(certificateURI);
        try {
            // Connect and parse the response on success
            HttpResponse response = httpClient.executeRequest(request);
            int responseCode = response.getStatusLine().getStatusCode();

            if (responseCode == HttpStatus.SC_OK) {
                try (InputStream inputStream = response.getEntity().getContent()) {
                    return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
                }
            }
            else {
                // Request was not successful
                String errorString = "Unable to get content: response code " + responseCode +
                        " connecting to " + request.getURI();
                LOGGER.error(errorString);
                throw new IOException(errorString);
            }
        }
        catch (NoRouteToHostException ex) {
            String errorString = "No route to download content";
            LOGGER.error(errorString, ex);
            throw new IOException(errorString);
        }
        catch (IOException ioEx) {
            LOGGER.error("Unable to download content: {} {}", urlIn, ioEx);
            throw ioEx;
        }
        finally {
            request.releaseConnection();
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
    public static Optional<X509CRL> parseCrl(String pemCrlCertificate) throws CertificateException {
        if (StringUtils.isEmpty(pemCrlCertificate)) {
            return Optional.empty();
        }

        try (InputStream inputStream = new ByteArrayInputStream(pemCrlCertificate.getBytes(StandardCharsets.UTF_8))) {
            return parseCrl(inputStream);
        }
        catch (IOException | CRLException ex) {
            throw new CertificateParsingException("Unable to load certificate from byte array", ex);
        }
    }

    /**
     * Parse a given PEM certificate
     * @param inputStream the input stream containing the PEM certificate
     * @return the certificate
     * @throws CertificateException when an error occurs while parsing the data
     */
    public static Optional<X509CRL> parseCrl(InputStream inputStream) throws CertificateException, CRLException {
        if (inputStream == null) {
            return Optional.empty();
        }

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return Optional.of((X509CRL)certificateFactory.generateCRL(inputStream));
    }

}
