/*
 * Copyright (c) 2026 SUSE LLC
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

package com.redhat.rhn.taskomatic.task;

import com.redhat.rhn.common.hibernate.LookupException;
import com.redhat.rhn.frontend.xmlrpc.EntityNotExistsFaultException;
import com.redhat.rhn.frontend.xmlrpc.TaskomaticApiException;
import com.redhat.rhn.frontend.xmlrpc.UnsupportedOperationException;

import com.suse.manager.attestation.AttestationDisabledException;
import com.suse.manager.attestation.AttestationManager;
import com.suse.manager.model.attestation.CoCoAttestationResult;
import com.suse.manager.model.attestation.CoCoResultStatus;
import com.suse.manager.model.attestation.ServerCoCoAttestationReport;

import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;

import java.util.List;

/**
 * Schedules confidential computing attestations on minions
 *
 */
public class CoCoAttestatorTask extends RhnJavaJob {

    /**
     * default constructor
     */
    public CoCoAttestatorTask() {
        this(new AttestationManager());
    }

    /**
     * constructor
     *
     * @param attestationManagerIn an instance of AttestationManager.
     */
    public CoCoAttestatorTask(AttestationManager attestationManagerIn) {
        this.attestationManager = attestationManagerIn;
    }

    private final AttestationManager attestationManager;


    @Override
    public String getConfigNamespace() {
        return "coco_attestator";
    }

    @Override
    public void execute(JobExecutionContext context) throws JobExecutionException {
        log.info("Schedules confidential computing attestations on minions");

        try {
            List<ServerCoCoAttestationReport> queuedReports = attestationManager.listCoCoQueuedReports();

            for (ServerCoCoAttestationReport report : queuedReports) {
                if (report.getResults().stream()
                        .map(CoCoAttestationResult::getStatus)
                        .allMatch(status -> CoCoResultStatus.QUEUED == status)) {
                    attestationManager.sumbitAttestationAction(report);
                }
            }
        }
        catch (LookupException e) {
            throw new EntityNotExistsFaultException(e);
        }
        catch (AttestationDisabledException e) {
            throw new UnsupportedOperationException(e);
        }
        catch (com.redhat.rhn.taskomatic.TaskomaticApiException e) {
            throw new TaskomaticApiException(e.getMessage());
        }

        log.info("Done Schedules confidential computing attestations on minions");
    }

}
