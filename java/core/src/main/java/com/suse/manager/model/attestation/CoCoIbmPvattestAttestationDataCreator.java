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

import com.suse.manager.webui.utils.gson.CoCoSettingsJson;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CoCoIbmPvattestAttestationDataCreator extends CoCoAttestationDataCreator {

    private String attestationRequestBin = "";
    private String attestationProtectionKeyBin = "";

    @Override
    public Map<String, Object> buildAttestationInputData(ServerCoCoAttestationConfig config) {
        Map<String, Object> outMap = new HashMap<>();

        outMap.put(NONCE_TAG, createBase64EncodedRandomNonce(256));

        //get attestation request from config (base 64 of binary file)
        Map<String, Object> inData = config.getInData();
        String hostKeyDocument = CoCoSettingsJson.extractHostKeyDocument(inData);
        //String secureExtensionHeader = CoCoSettingsJson.extractSecureExtensionHeader(inData);

        createAttestationRequest(hostKeyDocument);
        outMap.put(ATTESTATION_REQUEST_TAG, Base64.getEncoder().encodeToString(attestationRequestBin.getBytes()));
        outMap.put(ATTESTATION_PROTECTION_KEY_TAG, Base64.getEncoder().encodeToString(attestationProtectionKeyBin.getBytes()));

        return outMap;
    }

    protected void createAttestationRequest(String hostKeyDocument) {
        attestationRequestBin = "pvattest create -v \n" +
                "-k input/host_key_document.crt [" + hostKeyDocument + "]\n" +
                "--no-verify \n" +
                "-o output/attestation_request.bin\n" +
                "-a output/attestation_protection_key.key \n" +
                "--add-data phkh-img \n" +
                "--add-data phkh-att" +
                "a".repeat(500);

        attestationProtectionKeyBin = "0123456789ABCDEF0123456789abcdef";
    }

}

