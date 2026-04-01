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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class CoCoAttestationRequestDataCarlo2 {

    private List<CoCoAbstractTestAttestationRequestData> chunks = new ArrayList<>();

    /**
     * Constructor
     */
    public CoCoAttestationRequestDataCarlo2() {
    }

    /**
     * @param jsonResult dummy
     */
    public void parse(JsonElement jsonResult) {
        chunks.clear();
        chunks.add(Json.GSON.fromJson(jsonResult, CoCoAmdEpycAttestationRequestData.class));
        chunks.add(Json.GSON.fromJson(jsonResult, CoCoIbmPvattestAttestationRequestData.class));
        chunks.add(Json.GSON.fromJson(jsonResult, CoCoSecureBootAttestationRequestData.class));
    }

    /**
     * @return dummy
     */
    public Map<String, Object> asMap() {
        Map<String, Object> out = new HashMap<>();

        chunks.forEach(c -> out.putAll(c.asMap()));

        return out;
    }

    /**
     * @return dummy
     */

    //with this solution, even asMap() method in CoCoAbstractTestAttestationRequestData and derived classes can be dropped
    public Map<String, Object> asMapAlternative() {
        Map<String, Object> out = new HashMap<>();

        chunks.stream()
                .flatMap(c -> c.getResults().entrySet().stream())
                .forEach(
                        e -> {
                            e.getValue().ifPresent(c -> {
                                if (!c.getChanges().getStdout().isEmpty()) {
                                    out.put(e.getKey(), c.getChanges().getStdout());
                                }
                                else {
                                    out.put(e.getKey(), c.getChanges().getStderr());
                                }
                            });
                        });

        return out;
    }

    /**
     * @param key dummy
     * @return dummy
     */
    // this substitutes calls like requestData.getVlekCertificate()
    // with calls like requestData.getResult("mgr_vlek_certificate")
    // or even better requestData.getResult(CoCoAmdEpycAttestationRequestData.VLEK_CERTIFICATE_KEY)
    public Optional<StateApplyResult<CmdResult>> getResult(String key) {

        return chunks.stream()
                .map(CoCoAbstractTestAttestationRequestData::getResults)
                .filter(r -> r.containsKey(key))
                .findFirst()
                .flatMap(item -> item.get(key));
    }

}
