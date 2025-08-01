/*
 * Copyright (c) 2016--2023 SUSE LLC
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
package com.redhat.rhn.taskomatic.task.sshservice;

import com.redhat.rhn.common.hibernate.HibernateFactory;
import com.redhat.rhn.domain.action.ActionFactory;
import com.redhat.rhn.domain.server.MinionServer;
import com.redhat.rhn.domain.server.MinionServerFactory;
import com.redhat.rhn.taskomatic.task.checkin.SystemSummary;
import com.redhat.rhn.taskomatic.task.threaded.QueueWorker;
import com.redhat.rhn.taskomatic.task.threaded.TaskQueue;

import com.suse.manager.reactor.messaging.ApplyStatesEventMessage;
import com.suse.manager.utils.SaltUtils;
import com.suse.manager.webui.services.SaltServerActionService;
import com.suse.manager.webui.services.iface.SaltApi;
import com.suse.manager.webui.services.impl.SaltSSHService;
import com.suse.manager.webui.utils.salt.custom.SystemInfo;
import com.suse.salt.netapi.calls.LocalCall;
import com.suse.salt.netapi.calls.modules.State;
import com.suse.salt.netapi.datatypes.target.MinionList;
import com.suse.salt.netapi.exception.SaltException;
import com.suse.salt.netapi.results.Result;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.Logger;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * SSH Service worker for checking in ssh-push systems and resuming action chains via Salt SSH.
 */
public class SSHServiceWorker implements QueueWorker {

    private final Logger log;
    private final SystemSummary system;
    private TaskQueue parentQueue;

    private final SaltApi saltApi;
    private final SaltSSHService saltSSHService;
    private final SaltServerActionService saltServerActionService;
    private final SaltUtils saltUtils;


    /**
     * Constructor.
     * @param logger Logger for this instance
     * @param systemIn the system to work with
     * @param saltServiceIn the salt service to work with
     * @param saltSSHServiceIn the {@link SaltSSHService} to work with
     * @param saltServerActionServiceIn the {@link SaltServerActionService} to work with
     * @param saltUtilsIn the {@link SaltUtils} to work with
     */
    public SSHServiceWorker(Logger logger, SystemSummary systemIn,
                            SaltApi saltServiceIn, SaltSSHService saltSSHServiceIn,
                            SaltServerActionService saltServerActionServiceIn, SaltUtils saltUtilsIn) {
        log = logger;
        system = systemIn;
        saltApi = saltServiceIn;
        saltSSHService = saltSSHServiceIn;
        saltServerActionService = saltServerActionServiceIn;
        saltUtils = saltUtilsIn;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setParentQueue(TaskQueue queue) {
        parentQueue = queue;
    }

    /**
     * Looking for minions which either reached the checkin timeout and needs to be
     * tested if they are still alive or are in "rebooting" state and needs to be checked
     * if they are up again.
     */
    @Override
    public void run() {
        try {
            parentQueue.workerStarting();

            MinionServerFactory.lookupById(system.getId()).ifPresent(m -> {
                log.info("Executing actions for minion: {}", m.getMinionId());

                boolean checkinNeeded = true;
                if (system.isRebooting()) {
                    // System is rebooting, check if there's an action chain execution pending and resume it.
                    // If the action chain resumes it also checks in the system.
                    checkinNeeded = !resumeActionChainIfPending(m);
                }

                // Perform a check-in if there is no pending actions
                if (checkinNeeded) {
                    performCheckin(m);
                }

                // update uptime, etc and set Reboot Actions to COMPLETED
                updateSystemInfo(new MinionList(m.getMinionId()));
                log.debug("Nothing left to do for {}, exiting worker", m.getMinionId());
            });
        }
        catch (Exception e) {
            log.error(e.getMessage(), e);
            HibernateFactory.rollbackTransaction();
        }
        finally {
            parentQueue.workerDone();
            HibernateFactory.closeSession();

            // Finished talking to this system
            SSHServiceDriver.getCurrentSystems().remove(system);
        }
    }

    /**
     * Try to resume an action chain execution.
     * @param minion the ssh-push minion
     * @return true if there was an action chain execution pending and it was resumed successfully
     */
    private boolean resumeActionChainIfPending(MinionServer minion) {
        Map<String, Result<Map<String, String>>> pendingResume;
        try {
            // first check if there's any pending action chain execution on the minion
            // fetch the extra_filerefs and next_action_id
            pendingResume = saltApi.getPendingResume(Collections.singletonList(minion.getMinionId()));
        }
        catch (SaltException e) {
            log.error("Could not retrive pending action chain executions for minion", e);
            // retry later and skip performing the check-in
            return false;
        }

        if (pendingResume.isEmpty()) {
            log.debug("Minion {} is probably not up. Checking later for pending action chain executions.",
                    minion.getMinionId());
            return false;
        }

        Optional<Map<String, String>> confValues = pendingResume.get(minion.getMinionId()).fold(err -> {
                    log.error("mgractionchains.get_pending_resume failed for ssh minion: {}", err.fold(
                            Object::toString,
                            Object::toString,
                            Object::toString,
                            Object::toString,
                            Object::toString
                    ));
                    saltSSHService.cleanPendingActionChainAsync(minion);
                    return Optional.empty();
                },
                Optional::of);

        if (confValues.isEmpty() || confValues.get().isEmpty()) {
            log.debug("No action chain execution pending on minion {}", minion.getMinionId());
            return false;
        }

        Map<String, String> values = confValues.get();
        String extraFileRefs = values.get("ssh_extra_filerefs");
        String nextActionIdStr = values.get("next_action_id");
        String nextChunk = values.get("next_chunk");
        String currentBoot = values.get("current_boot_time");
        String persistBoot = values.get("persist_boot_time");

        if (StringUtils.isBlank(currentBoot)) {
            log.error("Could not resume pending action chain execution, no current_boot_time returned by " +
                    "mgractionchains.get_pending_resume for ssh minion {}", minion.getMinionId());
            saltSSHService.cleanPendingActionChainAsync(minion);
            return false;
        }

        if (StringUtils.isBlank(persistBoot)) {
            log.error("Could not resume pending action chain execution, no persist_boot_time returned by " +
                    "mgractionchains.get_pending_resume for ssh minion {}", minion.getMinionId());
            saltSSHService.cleanPendingActionChainAsync(minion);
            return false;
        }

        if (StringUtils.isBlank(nextActionIdStr)) {
            log.error("Could not resume pending action chain execution, no next_action_id returned by " +
                    "mgractionchains.get_pending_resume for ssh minion {}", minion.getMinionId());
            saltSSHService.cleanPendingActionChainAsync(minion);
            return false;
        }
        Optional<Long> nextActionId;
        try {
            nextActionId = Optional.of(Long.parseLong(nextActionIdStr));
        }
        catch (NumberFormatException e) {
            log.error("Action chain can't be resumed. next_action_id is not a valid number", e);
            saltSSHService.cleanPendingActionChainAsync(minion);
            return false;
        }

        if (StringUtils.isBlank(nextChunk)) {
            log.error("Could not resume pending action chain execution, no next_chunk returned by " +
                    "mgractionchains.get_pending_resume for ssh minion {}", minion.getMinionId());
            saltSSHService.cleanPendingActionChainAsync(minion);
            saltServerActionService.failActionChain(minion.getMinionId(), nextActionId,
                    Optional.of("Could not resume pending action chain execution, no next_chunk returned by " +
                            "mgractionchains.get_pending_resume"));
            return false;
        }

        if (StringUtils.isBlank(extraFileRefs)) {
            log.error("Could not resume pending action chain execution, no ssh_extra_filerefs returned by " +
                    "mgractionchains.get_pending_resume for ssh minion {}", minion.getMinionId());
            saltSSHService.cleanPendingActionChainAsync(minion);
            saltServerActionService.failActionChain(minion.getMinionId(), nextActionId,
                    Optional.of("Could not resume pending action chain execution, no ssh_extra_filerefs " +
                            "returned by mgractionchains.get_pending_resume"));
            return false;
        }

        Optional<LocalDateTime> currentBootTime = parseDateTime(minion, currentBoot);
        if (currentBootTime.isEmpty()) {
            return false;
        }
        Optional<LocalDateTime> persistBootTime = parseDateTime(minion, persistBoot);
        if (persistBootTime.isEmpty()) {
            return false;
        }

        // status.uptime returns a few miliseconds of difference in the boot time between subsequent invocations
        // even when the boot time stays the same
        long timeDelta = Math.abs(
                currentBootTime.get().toLocalTime().toSecondOfDay() -
                        persistBootTime.get().toLocalTime().toSecondOfDay());

        if (timeDelta < 3) {
            // don't resume the action chain, the system hasn't rebooted yet
            log.info("Not resuming action chain execution. Minion {} hasn't rebooted yet", minion.getMinionId());
            return false;
        }

        boolean nextActionIsFailed = nextActionId
                .map(ActionFactory::lookupById)
                .flatMap(action -> action.getServerActions().stream()
                        .filter(sa -> sa.getServer().equals(minion)).findFirst())
                .filter(sa -> sa.isStatusFailed())
                .isPresent();
        if (nextActionIsFailed) {
            // Next action is failed due to some previous error in the action chain.
            // This means action chain is already failed, remove pending action chain execution
            saltSSHService.cleanPendingActionChainAsync(minion);
            return false;
        }

        try {
            Map<String, Result<Map<String, State.ApplyResult>>> res = saltSSHService.callSyncSSH(
                    State.apply("actionchains.resumessh"),
                    new MinionList(minion.getMinionId()),
                    Optional.of(extraFileRefs));

            Result<Map<String, State.ApplyResult>> chunkResult = res.get(minion.getMinionId());
            if (chunkResult != null) {
                Optional<Map<String, State.ApplyResult>> optResult = chunkResult.result();
                if (optResult.isPresent()) {
                    return saltServerActionService
                            .handleActionChainSSHResult(nextActionId, minion.getMinionId(), optResult.get());
                }
                else {
                    String errMsg = chunkResult.error().map(saltErr -> saltErr.fold(
                            e ->  {
                                log.error(e);
                                return "Function " + e.getFunctionName() + " not available";
                            },
                            e ->  {
                                log.error(e);
                                return "Module " + e.getModuleName() + " not supported";
                            },
                            e ->  {
                                log.error(e);
                                return "Error parsing JSON: " + e.getJson();
                            },
                            e ->  {
                                log.error(e);
                                return "Salt error: " + e.getMessage();
                            },
                            e -> {
                                log.error(e);
                                return "Salt SSH error: " + e.getRetcode() + " " + e.getMessage();
                            }
                    )).orElse("Unknown error");

                    saltServerActionService.failActionChain(minion.getMinionId(), nextActionId,
                            Optional.of("Error handling action chain execution: " + errMsg));
                }
            }
            else {
                log.error("No action chain result for minion {}", minion.getMinionId());
                return false;
            }
        }
        catch (SaltException e) {
            log.error("Error resuming action on minion {}", minion.getMinionId(), e);
            return false;
        }

        return true;
    }

    private Optional<LocalDateTime> parseDateTime(MinionServer minion, String dateTimeString) {
        try {
            return Optional.of(LocalDateTime.parse(dateTimeString, DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        }
        catch (DateTimeParseException e) {
            log.error("Action chain can't be resumed. current_boot_time is not a valid date", e);
            saltSSHService.cleanPendingActionChainAsync(minion);
            return Optional.empty();
        }
    }

    private void performCheckin(MinionServer minion) {
        // Ping minion and perform check-in on success
        log.info("Performing a check-in for: {}", minion.getMinionId());
        Optional<Boolean> result = saltApi.ping(minion.getMinionId());

        result.ifPresent(res -> minion.updateServerInfo());
    }

    /**
     * Apply util.systeminfo state on the specified ssh-minion list in a synchronous away
     * @param minionTarget minion list
     */
    private void updateSystemInfo(MinionList minionTarget) {
        try {
            LocalCall<SystemInfo> systeminfo =
                    State.apply(List.of(ApplyStatesEventMessage.SYSTEM_INFO),
                    Optional.empty(), Optional.of(true), Optional.empty(), SystemInfo.class);
            Map<String, Result<SystemInfo>> systemInfoMap = saltSSHService.callSyncSSH(systeminfo, minionTarget);
            systemInfoMap.forEach((key, value) -> value.result().ifPresent(si -> {
                Optional<MinionServer> minionServer = MinionServerFactory.findByMinionId(key);
                minionServer.ifPresent(minion -> saltUtils.updateSystemInfo(si, minion));
            }));
        }
        catch (SaltException ex) {
            log.debug("Error while executing util.systeminfo state: {}", ex.getMessage());
        }
    }
}
