/*
 * Copyright (c) 2024 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 */

package com.suse.coco.model;

import java.util.Objects;
import java.util.StringJoiner;

/**
 * Represent the data required to get input data from attestation configuration
 */
public class AttestationConfigData {

    private long serverId;
    private String inData;


    public long getServerId() {
        return serverId;
    }

    public void setServerId(long serverIdIn) {
        this.serverId = serverIdIn;
    }

    public String getInData() {
        return inData;
    }

    public void setInData(String inDataIn) {
        inData = inDataIn;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AttestationConfigData configData)) {
            return false;
        }
        return (serverId == configData.serverId) && inData.equals(configData.inData);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverId, inData);
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", AttestationConfigData.class.getSimpleName() + "[", "]")
                .add("serverId=" + serverId)
                .add("inData=" + inData)
                .toString();
    }
}
