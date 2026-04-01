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

package com.suse.manager.model.attestation;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CoCoAttestationDataCreator {

    public static final String NONCE_TAG = "nonce";
    public static final String ATTESTATION_REQUEST_TAG = "attestation_request";
    public static final String ATTESTATION_PROTECTION_KEY_TAG = "attestation_protection_key";

    /**
     * @param config dummy
     * @return dummy
     */
    public Map<String, Object> buildAttestationInputData(ServerCoCoAttestationConfig config) {
        return new HashMap<>();
    }

    /**
     * @param nonceLength dummy
     * @return dummy
     */
    public String createBase64EncodedRandomNonce(int nonceLength) {
        SecureRandom rand = new SecureRandom();
        byte[] bytes = new byte[nonceLength];
        rand.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}
