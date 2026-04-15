/*
 * Copyright (c) 2024--2025 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 */
package com.redhat.rhn.domain.action;


import com.redhat.rhn.GlobalInstanceHolder;
import com.redhat.rhn.domain.action.server.ServerAction;
import com.redhat.rhn.domain.server.MinionSummary;

import com.suse.manager.attestation.AttestationManager;
import com.suse.manager.model.attestation.CoCoAttestationResult;
import com.suse.manager.model.attestation.CoCoResultStatus;
import com.suse.manager.utils.SaltUtils;
import com.suse.manager.webui.utils.salt.custom.coco.CoCoAttestationResponseDataParser;
import com.suse.salt.netapi.calls.LocalCall;
import com.suse.salt.netapi.calls.modules.State;

import com.google.gson.JsonElement;
import com.google.gson.JsonSyntaxException;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;

/**
 * CoCoAttestationAction - Class representing TYPE_COCO_ATTESTATION
 */
@Entity
@DiscriminatorValue("523")
public class CoCoAttestationAction extends Action {
    private static final Logger LOG = LogManager.getLogger(CoCoAttestationAction.class);

    @Override
    public void onFailAction(ServerAction serverActionIn) {
        if (!Objects.equals(serverActionIn.getParentAction(), this)) {
            LOG.error("This is not the action which belongs to the passed server action");
            return;
        }

        Optional<CoCoAttestationResult> optResult = getOptResult();
        if (optResult.isEmpty()) {
            LOG.error("Error in failing attestation action: failed to find a result entry");
            return;
        }
        CoCoAttestationResult result = optResult.get();
        result.setStatus(CoCoResultStatus.FAILED);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<LocalCall<?>, List<MinionSummary>> getSaltCalls(List<MinionSummary> minionSummaries) {
        Optional<CoCoAttestationResult> optResult = getOptResult();
        if (optResult.isEmpty()) {
            LOG.error("Error while computing salt calls for attestation: failed to find a result entry");
            return new HashMap<>();
        }

        CoCoAttestationResult result = optResult.get();
        String saltState = result.getResultType().getSaltState();
        if (StringUtils.isBlank(saltState)) {
            LOG.error("Error while computing salt calls for attestation: salt state not found, result {} id = {}",
                    result.getResultType().getTypeLabel(), result.getId());

            return new HashMap<>();
        }

        //pillar data sent to minion during coco attestation is cryptographically safe by design!
        Optional<Map<String, Object>> pillarData = getPillarData(result, minionSummaries);

        return Map.of(State.apply(Collections.singletonList(saltState), pillarData), minionSummaries);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void handleUpdateServerAction(ServerAction serverAction, JsonElement jsonResult, UpdateAuxArgs auxArgs) {

        Optional<CoCoAttestationResult> optResult = getOptResult();
        if (optResult.isEmpty()) {
            setFailure(serverAction, "Failed to find a result entry");
            return;
        }

        CoCoAttestationResult result = optResult.get();

        if (jsonResult == null) {
            setFailure(serverAction, result,
                    StringUtils.isBlank(serverAction.getResultMsg()) ?
                            "Got no result from system" : serverAction.getResultMsg());
            return;
        }

        try {
            CoCoAttestationResponseDataParser responseDataParser = new CoCoAttestationResponseDataParser();
            responseDataParser.parse(jsonResult);

            result.setOutData(responseDataParser.asMap());
            result.setStatus(CoCoResultStatus.PENDING);
        }
        catch (JsonSyntaxException e) {
            setFailure(serverAction, result,
                    "Failed to parse the attestation result:%n%s".formatted(
                            Optional.of(jsonResult).map(JsonElement::toString).orElse("Got no result")));
            return;
        }

        if (serverAction.isStatusFailed()) {
            setFailure(serverAction, result, SaltUtils.getJsonResultWithPrettyPrint(jsonResult));
        }
        else {
            serverAction.setResultMsg("Successfully collected attestation data response");
        }
    }

    private Optional<CoCoAttestationResult> getOptResult() {
        AttestationManager mgr = GlobalInstanceHolder.ATTESTATION_MANAGER;
        return mgr.lookupResultByAction(this);
    }

    private void setFailure(ServerAction serverAction, String errorMessage) {
        serverAction.setStatusFailed();
        serverAction.setResultMsg("Error while handling attestation data response from target system:%n%s"
                .formatted(errorMessage));
        LOG.error(errorMessage);
    }

    private void setFailure(ServerAction serverAction, CoCoAttestationResult result, String errorMessage) {
        setFailure(serverAction, errorMessage);
        result.setProcessOutput(errorMessage);
        result.setStatus(CoCoResultStatus.FAILED);
    }

    private Optional<Map<String, Object>> getPillarData(CoCoAttestationResult result,
                                                        List<MinionSummary> minionSummaries) {
        if (minionSummaries.isEmpty()) {
            return Optional.empty();
        }

        Map<String, Object> pillarData = new HashMap<>();

        Map<String, Object> attestationPillar = new HashMap<>(result.getInData());
        attestationPillar.put("environment_type", result.getEnvironmentType().name());

        pillarData.put("attestation_data", attestationPillar);

        return Optional.of(pillarData);
    }

}
