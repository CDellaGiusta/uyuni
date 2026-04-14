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

import com.suse.common.utilities.CertificateHelper;

import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class PvattestWrapperValidityChecker {
    private String validityError = "";
    private String logValidityError = "";

    /**
     * @return validity error string
     */
    public String getValidityError() {
        return validityError;
    }

    /**
     * @return longer error string to be logged
     */
    public String getLogValidityError() {
        return logValidityError;
    }

    private void setExceptionError(String prefix, Exception ex) {
        logValidityError = prefix + ex.getMessage();

        if (null != ex.getCause()) {
            validityError = prefix + ex.getCause().getLocalizedMessage();
        }
        else {
            validityError = prefix + ex.getLocalizedMessage();
        }
    }

    /**
     * @param hostKeyDocumentContent the host key document to validate
     * @return true if valid, false otherwise
     */
    public boolean isValidHostKeyDocument(String hostKeyDocumentContent) {
        validityError = "";
        logValidityError = "";

        try {
            X509Certificate hostKeyDocument = CertificateHelper.parse(hostKeyDocumentContent);
            hostKeyDocument.checkValidity();
        }
        catch (CertificateNotYetValidException nyvex) {
            setExceptionError("Certificate not yet valid: ", nyvex);
            return false;
        }
        catch (CertificateExpiredException eex) {
            setExceptionError("Certificate expired: ", eex);
            return false;
        }
        catch (CertificateException ex) {
            setExceptionError("", ex);
            return false;
        }

        return true;
    }

    /**
     * @param secureExecutionHeaderContentBase64 the Secure Execution Header to validate
     * @return true if valid, false otherwise
     */
    public boolean isValidSecureExecutionHeader(String secureExecutionHeaderContentBase64) {
        validityError = "";
        logValidityError = "";

        byte[] secureExecutionHeader;

        try {
            secureExecutionHeader =
                    Base64.getDecoder().decode(secureExecutionHeaderContentBase64.replace("\n", ""));
        }
        catch (Exception ex) {
            setExceptionError("", ex);
            return false;
        }

        if (0 == secureExecutionHeader.length) {
            validityError = "empty";
            logValidityError = validityError;
            return false;
        }

        int minLength = 8;
        if (secureExecutionHeader.length <= minLength) {
            validityError = "too short";
            logValidityError = validityError;
            return false;
        }

        //Magic number 8 bytes: 49 42 4D 53 65 63 45 78 ("IBMSecEx")
        char[] magicNumber = "IBMSecEx".toCharArray();
        for (int i = 0; i < magicNumber.length; i++) {
            if (secureExecutionHeader[i] != magicNumber[i]) {
                validityError = "invalid header";
                logValidityError = validityError;
                return false;
            }
        }

        return true;
    }
}
