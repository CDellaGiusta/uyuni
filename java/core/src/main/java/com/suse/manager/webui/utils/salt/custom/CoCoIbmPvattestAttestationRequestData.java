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

import com.google.gson.annotations.SerializedName;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class CoCoIbmPvattestAttestationRequestData extends CoCoAbstractTestAttestationRequestData {
    @SerializedName(
            "cmd_|-mgr_pvattest_report_|-/usr/bin/cat /tmp/cocoattest/attestation_report.bin | /usr/bin/base64_|-run")
    private StateApplyResult<CmdResult> pvattestReport;


    public static final String PVATTEST_REPORT_KEY = "mgr_pvattest_report";

    @Override
    public Map<String, Optional<StateApplyResult<CmdResult>>> getResults() {
        Map<String, Optional<StateApplyResult<CmdResult>>> out = new HashMap<>();
        out.put(PVATTEST_REPORT_KEY, Optional.ofNullable(pvattestReport));
        return out;
    }

    /**
     * @return dummy
     */
    public Optional<StateApplyResult<CmdResult>> getPvattestReport() {
        return Optional.ofNullable(pvattestReport);
    }


    @Override
    public Map<String, Object> asMap() {
        Map<String, Object> out = new HashMap<>();
        getPvattestReport()
                .map(StateApplyResult::getChanges)
                .ifPresent(c -> {
                    if (c.getRetcode() == 0) {
                        out.put(PVATTEST_REPORT_KEY, c.getStdout());
                    }
                });

        return out;
    }

}
