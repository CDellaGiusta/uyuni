/*
 * Copyright (c) 2024 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */

package com.suse.manager.webui.utils.gson;

import com.suse.manager.model.attestation.CoCoEnvironmentType;
import com.suse.manager.model.attestation.ServerCoCoAttestationConfig;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;

public class CoCoSettingsJson {
    private final boolean supported;

    private final boolean enabled;

    private final CoCoEnvironmentType environmentType;

    private final boolean attestOnBoot;

    //IBM specific
    private String hostKeyDocument;

    public String getHostKeyDocument() {
        return hostKeyDocument;
    }

    public void setHostKeyDocument(String hostKeyDocumentIn) {
        hostKeyDocument = hostKeyDocumentIn;
    }

    private String secureExtensionHeader;

    public String getSecureExtensionHeader() {
        return secureExtensionHeader;
    }

    public void setSecureExtensionHeader(String secureExtensionHeaderIn) {
        secureExtensionHeader = secureExtensionHeaderIn;
    }

    /**
     * Builds a json configuration from an existing attestation config
     * @param attestationConfig the current attestation configuration
     */
    public CoCoSettingsJson(ServerCoCoAttestationConfig attestationConfig) {
        this(true, attestationConfig.isEnabled(), attestationConfig.getEnvironmentType(),
            attestationConfig.isAttestOnBoot());
    }

    /**
     * Creates an empty json configuration
     * @param supportedIn if confidential computing is supported
     */
    public CoCoSettingsJson(boolean supportedIn) {
        this(supportedIn, false, CoCoEnvironmentType.NONE, false);
    }

    /**
     * Default constructor
     * @param supportedIn if confidential computing is supported
     * @param enabledIn if the configuration is enabled
     * @param environmentTypeIn the environment type
     * @param attestOnBootIn true if attestation is performed on boot
     */
    public CoCoSettingsJson(boolean supportedIn, boolean enabledIn, CoCoEnvironmentType environmentTypeIn,
                            boolean attestOnBootIn) {
        this.supported = supportedIn;
        this.enabled = enabledIn;
        this.environmentType = environmentTypeIn;
        this.attestOnBoot = attestOnBootIn;
        this.hostKeyDocument = null;
        this.secureExtensionHeader = null;
    }

    public boolean isSupported() {
        return supported;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public CoCoEnvironmentType getEnvironmentType() {
        return environmentType;
    }

    public boolean isAttestOnBoot() {
        return attestOnBoot;
    }

    public static final String HKD_TAG = "host_key_document";
    public static final String SEH_TAG = "secure_extension_header";

    public Map<String, Object> getInData() {
        Map<String, Object> dataInMap = new HashMap<>();

        if (null != hostKeyDocument) {
            dataInMap.put(HKD_TAG, hostKeyDocument);
        }
        if (null != secureExtensionHeader) {
            dataInMap.put(SEH_TAG, secureExtensionHeader);
        }

        return dataInMap;
    }

    public static String extractHostKeyDocument(Map<String, Object> inData) {
        return (String) inData.getOrDefault(HKD_TAG, "");
    }

    public static String extractSecureExtensionHeader(Map<String, Object> inData) {
        return (String) inData.getOrDefault(SEH_TAG, "");
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof CoCoSettingsJson that)) {
            return false;
        }
        return supported == that.supported &&
            enabled == that.enabled &&
            attestOnBoot == that.attestOnBoot &&
            environmentType == that.environmentType &&
            hostKeyDocument.equals(that.hostKeyDocument) &&
            secureExtensionHeader.equals(that.secureExtensionHeader);
    }

    @Override
    public int hashCode() {
        return Objects.hash(supported, enabled, environmentType, attestOnBoot,
                hostKeyDocument, secureExtensionHeader);
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", CoCoSettingsJson.class.getSimpleName() + "[", "]")
            .add("supported=" + isSupported())
            .add("enabled=" + isEnabled())
            .add("environmentType=" + getEnvironmentType())
            .add("attestOnBoot=" + isAttestOnBoot())
            .add("hostKeyDocument=" + getHostKeyDocument())
            .add("secureExtensionHeader=" + getSecureExtensionHeader())

            .toString();
    }
}
