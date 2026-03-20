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

public class CoCoAmdEpycAttestationRequestData extends CoCoAbstractTestAttestationRequestData {

    @SerializedName("cmd_|-mgr_snpguest_report_|-/usr/bin/cat /tmp/cocoattest/report.bin | /usr/bin/base64_|-run")
    private StateApplyResult<CmdResult> snpguestResult;

    @SerializedName("cmd_|-mgr_vlek_certificate_|-/usr/bin/cat /tmp/cocoattest/vlek.pem_|-run")
    private StateApplyResult<CmdResult> vlekCertificateResult;

    public static final String SNP_GUEST_REPORT_KEY = "mgr_snpguest_report";
    public static final String VLEK_CERTIFICATE_KEY = "mgr_vlek_certificate";

    @Override
    public Map<String, Optional<StateApplyResult<CmdResult>>> getResults() {
        Map<String, Optional<StateApplyResult<CmdResult>>> out = new HashMap<>();
        out.put(SNP_GUEST_REPORT_KEY, Optional.ofNullable(snpguestResult));
        out.put(VLEK_CERTIFICATE_KEY, Optional.ofNullable(vlekCertificateResult));
        return out;
    }

    /**
     * @return dummy
     */
    public Optional<StateApplyResult<CmdResult>> getSnpguestReport() {
        return Optional.ofNullable(snpguestResult);
    }

    /**
     * @return dummy
     */
    public Optional<StateApplyResult<CmdResult>> getVlekCertificate() {
        return Optional.ofNullable(vlekCertificateResult);
    }

    @Override
    public Map<String, Object> asMap() {
        Map<String, Object> out = new HashMap<>();
        getSnpguestReport()
                .map(StateApplyResult::getChanges)
                .ifPresent(c -> {
                    if (c.getRetcode() == 0) {
                        out.put(SNP_GUEST_REPORT_KEY, c.getStdout());
                    }
                });

        getVlekCertificate()
                .map(StateApplyResult::getChanges)
                .ifPresent(c -> {
                    if (c.getRetcode() == 0) {
                        out.put(VLEK_CERTIFICATE_KEY, c.getStdout());
                    }
                });

        return out;
    }
}
