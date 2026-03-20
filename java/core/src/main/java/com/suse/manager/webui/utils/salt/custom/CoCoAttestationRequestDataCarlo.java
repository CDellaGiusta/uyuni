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

package com.suse.manager.webui.utils.salt.custom;

import com.suse.salt.netapi.results.CmdResult;
import com.suse.salt.netapi.results.StateApplyResult;
import com.suse.utils.Json;

import com.google.gson.JsonElement;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class CoCoAttestationRequestDataCarlo {

    private CoCoAmdEpycAttestationRequestData amdEpycAttestationRequestData = null;
    private CoCoSecureBootAttestationRequestData secureBootAttestationRequestData = null;

    /**
     * Constructor
     */
    public CoCoAttestationRequestDataCarlo() {
    }

    /**
     * @param jsonResult dummy
     */
    public void parse(JsonElement jsonResult) {
        amdEpycAttestationRequestData = Json.GSON.fromJson(jsonResult, CoCoAmdEpycAttestationRequestData.class);
        secureBootAttestationRequestData = Json.GSON.fromJson(jsonResult, CoCoSecureBootAttestationRequestData.class);

    }

    /**
     * @return dummy
     */
    public Map<String, Object> asMap() {
        Map<String, Object> out = new HashMap<>();

        out.putAll(amdEpycAttestationRequestData.asMap());
        out.putAll(secureBootAttestationRequestData.asMap());

        return out;
    }


    //ARE THEY REALLY NEEDED?
    public Optional<StateApplyResult<CmdResult>> getSnpguestReport() {
        return Optional.ofNullable(amdEpycAttestationRequestData)
                .flatMap(CoCoAmdEpycAttestationRequestData::getSnpguestReport);
    }
    public Optional<StateApplyResult<CmdResult>> getVlekCertificate() {
        return Optional.ofNullable(amdEpycAttestationRequestData)
                .flatMap(CoCoAmdEpycAttestationRequestData::getVlekCertificate);
    }
    public Optional<StateApplyResult<CmdResult>> getSecureBoot() {
        return Optional.ofNullable(secureBootAttestationRequestData)
                .flatMap(CoCoSecureBootAttestationRequestData::getSecureBoot);
    }


}
