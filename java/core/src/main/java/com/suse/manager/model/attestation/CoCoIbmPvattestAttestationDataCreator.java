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

import java.util.HashMap;
import java.util.Map;

public class CoCoIbmPvattestAttestationDataCreator extends CoCoAttestationDataCreator {

    @Override
    public Map<String, Object> buildAttestationInputData(ServerCoCoAttestationConfig config) {
        Map<String, Object> outMap = new HashMap<>();

        outMap.put(NONCE_TAG, createBase64EncodedRandomNonce(256));

        //get attestation request from config (base 64 of binary file)
        String attestationRequestDemo = config.toString() + "a".repeat(500);

        outMap.put(ATTESTATION_REQUEST_TAG, attestationRequestDemo);

        return outMap;
    }
}
