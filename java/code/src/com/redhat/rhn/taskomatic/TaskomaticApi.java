/*
 * Copyright (c) 2009--2017 Red Hat, Inc.
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
package com.redhat.rhn.taskomatic;

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;

import com.redhat.rhn.common.conf.ConfigDefaults;
import com.redhat.rhn.common.hibernate.HibernateFactory;
import com.redhat.rhn.common.security.PermissionException;
import com.redhat.rhn.common.validator.ValidatorException;
import com.redhat.rhn.domain.access.AccessGroupFactory;
import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.action.ActionChain;
import com.redhat.rhn.domain.action.ActionChainFactory;
import com.redhat.rhn.domain.action.channel.SubscribeChannelsAction;
import com.redhat.rhn.domain.action.server.ServerAction;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.ChannelFactory;
import com.redhat.rhn.domain.cloudpayg.PaygSshData;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.org.OrgFactory;
import com.redhat.rhn.domain.recurringactions.RecurringAction;
import com.redhat.rhn.domain.role.RoleFactory;
import com.redhat.rhn.domain.server.MinionServer;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.taskomatic.domain.TaskoSchedule;
import com.redhat.rhn.taskomatic.task.RepoSyncTask;

import com.suse.manager.model.hub.IssRole;
import com.suse.manager.utils.MinionServerUtils;
import com.suse.utils.CertificateUtils;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.MalformedURLException;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import redstone.xmlrpc.XmlRpcClient;
import redstone.xmlrpc.XmlRpcException;
import redstone.xmlrpc.XmlRpcFault;

/**
 * TaskomaticApi
 */
public class TaskomaticApi {

    public static final String MINION_ACTION_BUNCH_LABEL = "minion-action-executor-bunch";
    public static final String MINION_ACTION_JOB_PREFIX = "minion-action-executor-";
    public static final String MINION_ACTION_JOB_DOWNLOAD_PREFIX =
            MINION_ACTION_JOB_PREFIX + "download-";
    public static final String MINION_ACTIONCHAIN_BUNCH_LABEL = "minion-action-chain-executor-bunch";
    public static final String MINION_ACTIONCHAIN_JOB_PREFIX = "minion-action-chain-executor-";

    private static final String SCHEDULE_SINGLE_SAT_BUNCH_RUN = "tasko.scheduleSingleSatBunchRun";
    private static final Logger LOG = LogManager.getLogger(TaskomaticApi.class);


    private XmlRpcClient getClient() throws TaskomaticApiException {
        try {
            return new XmlRpcClient(
                    ConfigDefaults.get().getTaskoServerUrl(), false);
        }
        catch (MalformedURLException e) {
            throw new TaskomaticApiException(e);
        }
    }

    protected Object invoke(String name, Object... args) throws TaskomaticApiException {
        try {
            return getClient().invoke(name, args);
        }
        catch (XmlRpcException | XmlRpcFault e) {
            throw new TaskomaticApiException(e);
        }
    }

    /**
     * Returns whether taskomatic is running
     *
     * @return True if taskomatic is running
     */
    public boolean isRunning() {
        try {
            invoke("tasko.one", 0);
            return true;
        }
        catch (Exception e) {
            return false;
        }
    }

    /**
     * Schedule a single ssh minion action.
     *
     * @param actionIn  the action
     * @param sshMinion the Salt ssh minion
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSSHActionExecution(Action actionIn, MinionServer sshMinion)
            throws TaskomaticApiException {
        scheduleSSHActionExecution(actionIn, sshMinion, false);
    }

    /**
     * Schedule a single ssh minion action.
     *
     * @param actionIn                the action
     * @param sshMinion               the Salt ssh minion
     * @param forcePackageListRefresh force package list refresh when set to true
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSSHActionExecution(Action actionIn, MinionServer sshMinion, boolean forcePackageListRefresh)
            throws TaskomaticApiException {
        Map<String, String> scheduleParams = new HashMap<>();
        scheduleParams.put("action_id", Long.toString(actionIn.getId()));
        scheduleParams.put("force_pkg_list_refresh", Boolean.toString(forcePackageListRefresh));
        scheduleParams.put("ssh_minion_id", sshMinion.getMinionId());
        invoke(SCHEDULE_SINGLE_SAT_BUNCH_RUN,
                "ssh-minion-action-executor-bunch",
                StringUtils.substring(
                        "ssh-minion-action-executor-" + actionIn.getId() + "-" + sshMinion.getId(), 0, 50),
                scheduleParams,
                new Date());
    }


    /**
     * Schedule a single reposync
     *
     * @param chan the channel
     * @param user the user
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSingleRepoSync(Channel chan, User user)
            throws TaskomaticApiException {
        Map<String, Object> scheduleParams = new HashMap<>();
        scheduleParams.put("channel_id", chan.getId().toString());
        invoke("tasko.scheduleSingleBunchRun", user.getOrg().getId(),
                "repo-sync-bunch", scheduleParams);
    }

    /**
     * Schedule a single reposync for a given list of channels. This is scheduled from
     * within another taskomatic job, so we don't have a user here. We pass in the
     * satellite org to create the job label internally.
     *
     * @param channels list of channels
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSingleRepoSync(List<Channel> channels)
            throws TaskomaticApiException {
        List<String> channelIds = new ArrayList<>(channels.size());
        for (Channel channel : channels) {
            channelIds.add(channel.getId().toString());
        }
        Map<String, List<String>> scheduleParams = new HashMap<>();
        scheduleParams.put("channel_ids", channelIds);
        invoke("tasko.scheduleSingleBunchRun", OrgFactory.getSatelliteOrg().getId(),
                "repo-sync-bunch", scheduleParams);
    }

    /**
     * Schedule a single reposync
     *
     * @param chan   the channel
     * @param user   the user
     * @param params parameters
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSingleRepoSync(Channel chan, User user, Map<String, String> params)
            throws TaskomaticApiException {

        Map<String, String> scheduleParams = new HashMap<>();
        scheduleParams.put("channel_id", chan.getId().toString());
        scheduleParams.putAll(params);

        invoke("tasko.scheduleSingleBunchRun", user.getOrg().getId(),
                "repo-sync-bunch", scheduleParams);
    }

    private String createRepoSyncScheduleName(Channel chan, User user) {
        return "repo-sync-" + user.getOrg().getId() + "-" + chan.getId();
    }

    /**
     * Schedule a recurring reposync
     *
     * @param chan the channel
     * @param user the user
     * @param cron the cron format
     * @return the Date?
     * @throws TaskomaticApiException if there was an error
     */
    public Date scheduleRepoSync(Channel chan, User user, String cron)
            throws TaskomaticApiException {
        String jobLabel = createRepoSyncScheduleName(chan, user);

        Map<String, Object> task = findScheduleByBunchAndLabel("repo-sync-bunch", jobLabel, user);
        if (task != null) {
            unscheduleRepoTask(jobLabel, user);
        }
        Map<String, String> scheduleParams = new HashMap<>();
        scheduleParams.put("channel_id", chan.getId().toString());
        return (Date) invoke("tasko.scheduleBunch", user.getOrg().getId(),
                "repo-sync-bunch", jobLabel, cron, scheduleParams);
    }

    /**
     * Schedule a recurring reposync
     *
     * @param chan   the channel
     * @param user   the user
     * @param cron   the cron format
     * @param params parameters
     * @return the Date?
     * @throws TaskomaticApiException if there was an error
     */
    public Date scheduleRepoSync(Channel chan, User user, String cron,
                                 Map<String, String> params) throws TaskomaticApiException {
        String jobLabel = createRepoSyncScheduleName(chan, user);

        Map<String, Object> task = findScheduleByBunchAndLabel("repo-sync-bunch", jobLabel, user);
        if (task != null) {
            unscheduleRepoTask(jobLabel, user);
        }
        Map<String, String> scheduleParams = new HashMap<>();
        scheduleParams.put("channel_id", chan.getId().toString());
        scheduleParams.putAll(params);

        return (Date) invoke("tasko.scheduleBunch", user.getOrg().getId(),
                "repo-sync-bunch", jobLabel, cron, scheduleParams);
    }

    /**
     * Creates a new single satellite schedule
     *
     * @param user      shall be sat admin
     * @param bunchName bunch name
     * @param params    parameters for the bunch
     * @return date of the first schedule
     * @throws TaskomaticApiException if there was an error
     */
    public Date scheduleSingleSatBunch(User user, String bunchName,
                                       Map<String, String> params) throws TaskomaticApiException {
        ensureSatAdminRole(user);
        return (Date) invoke(SCHEDULE_SINGLE_SAT_BUNCH_RUN, bunchName, params);
    }

    /**
     * Creates a new single gatherer schedule
     *
     * @param user   shall be org admin
     * @param params parameters for the bunch
     * @return date of the first schedule
     * @throws TaskomaticApiException if there was an error
     */
    public Date scheduleGathererRefresh(User user, Map<String, String> params) throws TaskomaticApiException {
        ensureOrgAdminRole(user);
        return (Date) invoke(SCHEDULE_SINGLE_SAT_BUNCH_RUN, "gatherer-matcher-bunch", params);
    }

    /**
     * Validates user has sat admin role
     *
     * @param user shall be sat admin
     * @throws PermissionException if there was an error
     */
    private void ensureSatAdminRole(User user) {
        if (!user.hasRole(RoleFactory.SAT_ADMIN)) {
            ValidatorException.raiseException("satadmin.jsp.error.notsatadmin",
                    user.getLogin());
        }
    }

    /**
     * Validates user has org admin role
     *
     * @param user shall be org admin
     * @throws PermissionException if there was an error
     */
    private void ensureOrgAdminRole(User user) {
        if (!user.hasRole(RoleFactory.ORG_ADMIN)) {
            throw new PermissionException(RoleFactory.ORG_ADMIN);
        }
    }

    /**
     * Validates user has channel admin role
     *
     * @param user shall be channel admin
     * @throws PermissionException if there was an error
     */
    private void ensureChannelAdminRole(User user) {
        if (!user.isMemberOf(AccessGroupFactory.CHANNEL_ADMIN)) {
            throw new PermissionException(AccessGroupFactory.CHANNEL_ADMIN);
        }
    }

    /**
     * Creates a new schedule, unschedules, if en existing is defined
     *
     * @param user      shall be sat admin
     * @param jobLabel  name of the schedule
     * @param bunchName bunch name
     * @param cron      cron expression
     * @return date of the first schedule
     * @throws TaskomaticApiException if there was an error
     */
    public Date scheduleSatBunch(User user, String jobLabel, String bunchName, String cron)
            throws TaskomaticApiException {
        ensureSatAdminRole(user);
        return doScheduleSatBunch(user, jobLabel, bunchName, cron);
    }

    /**
     * Schedule a recurring action
     *
     * @param action the {@link RecurringAction}
     * @param user   the scheduler user
     * @throws PermissionException    when given user does not have permissions for scheduling given action
     * @throws TaskomaticApiException on Taskomatic error
     */
    public void scheduleRecurringAction(RecurringAction action, User user) throws TaskomaticApiException {
        if (!action.canAccess(user)) {
            throw new PermissionException(String.format("User '%s' can't schedule action '%s'", user, action));
        }

        doScheduleSatBunch(user, action.computeTaskoScheduleName(), "recurring-action-executor-bunch",
                action.getCronExpr());
    }

    //helper method for scheduling bunch without permission checking
    private Date doScheduleSatBunch(User user, String jobLabel, String bunchName, String cron)
            throws TaskomaticApiException {
        Map<String, Object> task = findSatScheduleByBunchAndLabel(bunchName, jobLabel, user);
        if (task != null) {
            doUnscheduleSatTask(jobLabel);
        }
        return (Date) invoke("tasko.scheduleSatBunch", bunchName, jobLabel, cron, new HashMap<>());
    }

    /**
     * Activate a disables Sat Bunch again
     * @param user the user
     * @param jobLabel the job label
     * @param bunchName the bunch name
     * @return the Date of the first schedule
     * @throws TaskomaticApiException on Taskomatic error
     */
    public Date activateSatBunch(User user, String jobLabel, String bunchName) throws TaskomaticApiException {
        ensureSatAdminRole(user);
        return (Date) invoke("tasko.activateSatBunch", bunchName, jobLabel);
    }

    /**
     * Update a Sat Bunch
     * @param user the user
     * @param jobLabel the job label
     * @param bunchName the bunch name
     * @param cron the cron expression
     * @return the Date of the first schedule
     * @throws TaskomaticApiException on Taskomatic error
     */
    public Date updateSatBunch(User user, String jobLabel, String bunchName, String cron)
            throws TaskomaticApiException {
        ensureSatAdminRole(user);
        return (Date) invoke("tasko.updateSatBunch", bunchName, jobLabel, cron);
    }

    /**
     * Unschedule a recurring action
     *
     * @param action the {@link RecurringAction}
     * @param user   the unscheduler user
     * @throws PermissionException    when given user does not have permissions for unscheduling given action
     * @throws TaskomaticApiException on Taskomatic error
     */
    public void unscheduleRecurringAction(RecurringAction action, User user) throws TaskomaticApiException {
        if (!action.canAccess(user)) {
            throw new PermissionException(String.format("User '%s' can't unschedule action '%s'", user, action));
        }

        doUnscheduleSatBunch(user, action.computeTaskoScheduleName(), "recurring-action-executor-bunch");
    }

    //helper method for unscheduling bunch without permission checking
    private void doUnscheduleSatBunch(User user, String jobLabel, String bunchName)
            throws TaskomaticApiException {
        Map<String, Object> task = findSatScheduleByBunchAndLabel(bunchName, jobLabel, user);
        if (task != null) {
            doUnscheduleSatTask(jobLabel);
        }
    }

    private void doUnscheduleSatTask(String jobLabel) throws TaskomaticApiException {
        invoke("tasko.unscheduleSatBunches", singletonList(jobLabel));
    }

    /**
     * Unchedule a reposync task
     *
     * @param chan the channel
     * @param user the user
     * @throws TaskomaticApiException if there was an error
     */
    public void unscheduleRepoSync(Channel chan, User user) throws TaskomaticApiException {
        String jobLabel = createRepoSyncScheduleName(chan, user);
        Map<String, Object> task = findScheduleByBunchAndLabel("repo-sync-bunch", jobLabel, user);
        if (task != null) {
            unscheduleRepoTask(jobLabel, user);
        }
    }

    private void unscheduleRepoTask(String jobLabel, User user)
            throws TaskomaticApiException {
        ensureChannelAdminRole(user);
        invoke("tasko.unscheduleBunch", user.getOrg().getId(), jobLabel);
    }

    /**
     * unschedule satellite task
     *
     * @param jobLabel schedule name
     * @param user     shall be satellite admin
     * @throws TaskomaticApiException if there was an error
     */
    public void unscheduleSatTask(String jobLabel, User user)
            throws TaskomaticApiException {
        ensureSatAdminRole(user);
        invoke("tasko.unscheduleSatBunches", singletonList(jobLabel));
    }

    /**
     * Return list of all Sat schedules
     *
     * @param user shall be sat admin
     * @return list of schedules
     * @throws TaskomaticApiException if there was an error
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> findAllSatSchedules(User user) throws TaskomaticApiException {
        ensureSatAdminRole(user);
        return (List<Map<String, Object>>) invoke("tasko.listAllSatSchedules");
    }

    /**
     * Return list of bunch runs
     *
     * @param user      shall be sat admin
     * @param bunchName name of the bunch
     * @return list of schedules
     * @throws TaskomaticApiException if there was an error
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> findRunsByBunch(User user, String bunchName) throws TaskomaticApiException {
        return (List<Map<String, Object>>) invoke("tasko.listBunchSatRuns", bunchName);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> findScheduleByBunchAndLabel(String bunchName, String jobLabel, User user)
            throws TaskomaticApiException {
        List<Map<String, Object>> schedules = (List<Map<String, Object>>) invoke("tasko.listActiveSchedulesByBunch",
                user.getOrg().getId(), bunchName);
        for (Map<String, Object> schedule : schedules) {
            if (schedule.get("job_label").equals(jobLabel)) {
                return schedule;
            }
        }
        return null;
    }

    private Map<String, Object> findSatScheduleByBunchAndLabel(String bunchName, String jobLabel,
                                                               User user) throws TaskomaticApiException {
        List<Map<String, Object>> schedules = (List<Map<String, Object>>) invoke("tasko.listActiveSatSchedulesByBunch",
                bunchName);
        for (Map<String, Object> schedule : schedules) {
            if (schedule.get("job_label").equals(jobLabel)) {
                return schedule;
            }
        }
        return null;
    }

    /**
     * Check whether there's an active schedule of given job label
     *
     * @param jobLabel job label
     * @param user     the user
     * @return true, if schedule exists
     * @throws TaskomaticApiException if there was an error
     */
    public boolean satScheduleActive(String jobLabel, User user)
            throws TaskomaticApiException {
        List<Map<String, Object>> schedules = (List<Map<String, Object>>) invoke("tasko.listActiveSatSchedules");
        for (Map<String, Object> schedule : schedules) {
            if (schedule.get("job_label").equals(jobLabel)) {
                return Boolean.TRUE;
            }
        }
        return Boolean.FALSE;
    }

    /**
     * Get the cron format for a single channel
     *
     * @param chan the channel
     * @param user the user
     * @return the Cron format
     * @throws TaskomaticApiException if there was an error
     */
    public String getRepoSyncSchedule(Channel chan, User user)
            throws TaskomaticApiException {
        String jobLabel = createRepoSyncScheduleName(chan, user);
        Map<String, Object> task = findScheduleByBunchAndLabel("repo-sync-bunch", jobLabel, user);
        if (task == null) {
            return null;
        }
        return (String) task.get("cron_expr");
    }

    /**
     * Return list of available bunches
     *
     * @param user shall be sat admin
     * @return list of bunches
     * @throws TaskomaticApiException if there was an error
     */
    public List<Map<String, Object>> listSatBunchSchedules(User user) throws TaskomaticApiException {
        return (List<Map<String, Object>>) invoke("tasko.listSatBunches");
    }

    /**
     * looks up schedule according to id
     *
     * @param user       shall be sat admin
     * @param scheduleId schedule id
     * @return schedule
     * @throws TaskomaticApiException if there was an error
     */
    public Map<String, Object> lookupScheduleById(User user, Long scheduleId)
            throws TaskomaticApiException {
        return (Map<String, Object>) invoke("tasko.lookupScheduleById", scheduleId);
    }

    /**
     * looks up schedule according to label
     *
     * @param user          shall be sat admin
     * @param bunchName     bunch name
     * @param scheduleLabel schedule label
     * @return schedule
     * @throws TaskomaticApiException if there was an error
     */
    public Map<String, Object> lookupScheduleByBunchAndLabel(User user, String bunchName,
                                                             String scheduleLabel) throws TaskomaticApiException {
        return findSatScheduleByBunchAndLabel(bunchName, scheduleLabel, user);
    }

    /**
     * looks up bunch according to name
     *
     * @param user      shall be sat admin
     * @param bunchName bunch name
     * @return bunch
     * @throws TaskomaticApiException if there was an error
     */
    public Map<String, Object> lookupBunchByName(User user, String bunchName)
            throws TaskomaticApiException {
        return (Map<String, Object>) invoke("tasko.lookupBunchByName", bunchName);
    }

    /**
     * List all reposync schedules within an organization
     *
     * @param org organization
     * @return list of schedules
     */
    private List<TaskoSchedule> listActiveRepoSyncSchedules(Org org) {
        try {
            return TaskoFactory.listActiveSchedulesByOrgAndBunch(org.getId().intValue(),
                    "repo-sync-bunch");
        }
        catch (NoSuchBunchTaskException e) {
            // no such schedules available
            return new ArrayList<>();
        }
    }

    /**
     * unschedule all outdated repo-sync schedules within an org
     *
     * @param orgIn organization
     * @return number of removed schedules
     * @throws TaskomaticApiException if there was an error
     */
    public int unscheduleInvalidRepoSyncSchedules(Org orgIn) throws TaskomaticApiException {
        Set<String> unscheduledLabels = new HashSet<>();
        for (TaskoSchedule schedule : listActiveRepoSyncSchedules(orgIn)) {
            List<Long> channelIds = RepoSyncTask.getChannelIds(schedule.getDataMap());
            for (Long channelId : channelIds) {
                if (ChannelFactory.lookupById(channelId) == null) {
                    String label = schedule.getJobLabel();
                    if (!unscheduledLabels.contains(label)) {
                        invoke("tasko.unscheduleBunch", orgIn.getId(), label);
                        unscheduledLabels.add(label);
                    }
                }
            }
        }
        return unscheduledLabels.size();
    }

    /**
     * Schedule an Action execution for Salt minions.
     *
     * @param action                  the action to be executed
     * @param forcePackageListRefresh is a package list is requested
     * @param checkIfMinionInvolved   check if action involves minions
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleActionExecution(Action action, boolean forcePackageListRefresh, boolean checkIfMinionInvolved)
            throws TaskomaticApiException {
        if (checkIfMinionInvolved) {
            boolean minionsInvolved = HibernateFactory.getSession()
                    .getNamedQuery("Action.findMinionIds")
                    .setParameter("id", action.getId())
                    .setMaxResults(1)
                    .stream()
                    .findAny()
                    .isPresent();
            if (!minionsInvolved) {
                return;
            }
        }
        scheduleMinionActionExecutions(singletonList(action), forcePackageListRefresh);
    }

    /**
     * Schedule Actions execution for Salt minions.
     *
     * @param actions                 the list of actions to be executed
     * @param forcePackageListRefresh is a package list is requested
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleMinionActionExecutions(List<Action> actions, boolean forcePackageListRefresh)
            throws TaskomaticApiException {
        List<Map<String, String>> paramsList = new ArrayList<>();
        List<String> ids = new ArrayList<>();
        for (Action action : actions) {
            Map<String, String> params = new HashMap<>();
            String id = Long.toString(action.getId());
            params.put("action_id", id);
            params.put("force_pkg_list_refresh", Boolean.toString(forcePackageListRefresh));
            params.put("earliest_action", action.getEarliestAction().toInstant().toString());
            paramsList.add(params);
            ids.add(id);
        }
        LOG.debug("Scheduling actions: {}.", ids);
        invoke("tasko.scheduleRuns", MINION_ACTION_BUNCH_LABEL, MINION_ACTION_JOB_PREFIX, paramsList);
        LOG.debug("Actions scheduled: {}.", ids);
    }

    /**
     * Schedule an Action Chain execution for Salt minions.
     *
     * @param actionchain the actionchain to be executed
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleActionChainExecution(ActionChain actionchain)
            throws TaskomaticApiException {
        if (!ActionChainFactory.isActionChainTargettingMinions(actionchain)) {
            return;
        }

        Date earliestAction = actionchain.getEarliestAction();

        Map<String, String> params = new HashMap<>();
        params.put("actionchain_id", Long.toString(actionchain.getId()));

        invoke(SCHEDULE_SINGLE_SAT_BUNCH_RUN, MINION_ACTIONCHAIN_BUNCH_LABEL,
                MINION_ACTIONCHAIN_JOB_PREFIX + actionchain.getId(), params,
                earliestAction);
    }

    /**
     * Schedule a staging job for Salt minions.
     *
     * @param actionId        ID of the action to be executed
     * @param minionId        ID of the minion involved
     * @param stagingDateTime scheduling time of staging
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleStagingJob(Long actionId, Long minionId, Date stagingDateTime)
            throws TaskomaticApiException {
        Map<String, String> params = new HashMap<>();
        params.put("action_id", Long.toString(actionId));
        params.put("staging_job", "true");
        params.put("staging_job_minion_server_id", Long.toString(minionId));

        invoke(SCHEDULE_SINGLE_SAT_BUNCH_RUN, MINION_ACTION_BUNCH_LABEL,
                MINION_ACTION_JOB_DOWNLOAD_PREFIX + actionId + "-" + minionId, params,
                stagingDateTime);
    }

    /**
     * Schedule a staging job for Salt minions.
     *
     * @param actionData Map containing mapping between action and minions data
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleStagingJobs(Map<Long, Map<Long, ZonedDateTime>> actionData) throws TaskomaticApiException {
        List<Map<String, String>> paramList = actionData.entrySet()
                .stream()
                .flatMap(actionEntry -> actionEntry.getValue().entrySet().stream()
                        .map(minionData -> {
                            Map<String, String> params = new HashMap<>();
                            params.put("action_id", Long.toString(actionEntry.getKey()));
                            params.put("staging_job", "true");
                            params.put("staging_job_minion_server_id", Long.toString(minionData.getKey()));
                            params.put("earliest_action", minionData.getValue().toInstant().toString());
                            return params;
                        })).collect(Collectors.toList());
        invoke("tasko.scheduleRuns", MINION_ACTION_BUNCH_LABEL, MINION_ACTION_JOB_DOWNLOAD_PREFIX, paramList);
    }

    /**
     * Schedule an Action execution for Salt minions, without forced
     * package refresh.
     *
     * @param action the action to be executed
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleActionExecution(Action action)
            throws TaskomaticApiException {
        scheduleActionExecution(action, false);
    }

    /**
     * Schedule an Action execution for Salt minions.
     *
     * @param action                  the action to be executed
     * @param forcePackageListRefresh is a package list is requested
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleActionExecution(Action action, boolean forcePackageListRefresh)
            throws TaskomaticApiException {
        scheduleActionExecution(action, forcePackageListRefresh, true);
    }

    /**
     * Schedule a channel subscription action.
     *
     * @param user   the user that schedules the action
     * @param action the action to schedule
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSubscribeChannels(User user, SubscribeChannelsAction action)
            throws TaskomaticApiException {
        Map<String, String> params = new HashMap<>();
        params.put("action_id", Long.toString(action.getId()));
        params.put("user_id", Long.toString(user.getId()));
        invoke(SCHEDULE_SINGLE_SAT_BUNCH_RUN, MINION_ACTION_BUNCH_LABEL,
                MINION_ACTION_JOB_PREFIX + action.getId(), params,
                action.getEarliestAction());
    }

    /**
     * Delete several scheduled Actions.
     *
     * @param actionMap mapping from Actions to involved Servers
     * @throws TaskomaticApiException if there was an error
     */
    public void deleteScheduledActions(Map<Action, Set<Server>> actionMap)
            throws TaskomaticApiException {

        List<Action> actionsToBeUnscheduled = actionMap.entrySet().stream()
                // select Actions that have no minions besides those in the specified set
                // (those that have any other minion should NOT be unscheduled!)
                .filter(e -> e.getKey().getServerActions().stream()
                        .map(ServerAction::getServer)
                        .filter(MinionServerUtils::isMinionServer)
                        .allMatch(s -> e.getValue().contains(s))
                )
                .map(Map.Entry::getKey)
                .toList();

        Set<ActionChain> affectedActionChains = actionsToBeUnscheduled.stream()
                .map(a -> ActionChainFactory.getActionChainsByAction(a).orElse(null))
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        List<String> jobLabels = actionsToBeUnscheduled.stream()
                .map(a -> MINION_ACTION_JOB_PREFIX + a.getId())
                .filter(job -> !TaskoFactory.listScheduleByLabel(job).isEmpty())
                .collect(Collectors.toList());

        affectedActionChains.forEach(ac -> {
            List<Action> activeActionsForChain = ActionChainFactory.getActiveActionsForChain(ac);
            if (activeActionsForChain.removeAll(actionsToBeUnscheduled) && activeActionsForChain.isEmpty()) {
                jobLabels.add(MINION_ACTIONCHAIN_JOB_PREFIX + ac.getId());
            }
        });

        if (!jobLabels.isEmpty()) {
            LOG.debug("Unscheduling jobs: {}", jobLabels);
            invoke("tasko.unscheduleSatBunches", jobLabels);
        }
    }

    /**
     * Schedule a single reposync
     *
     * @param sshdata the payg ssh connection data
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSinglePaygUpdate(PaygSshData sshdata)
            throws TaskomaticApiException {
        Map<String, String> scheduleParams = new HashMap<>();
        scheduleParams.put("sshData_id", sshdata.getId().toString());
        invoke(SCHEDULE_SINGLE_SAT_BUNCH_RUN, "update-payg-data-bunch", scheduleParams);
    }

    /**
     * Check if the Taskomatic java process has JMX enabled.
     *
     * @return true is JMX enabled
     * @throws TaskomaticApiException if there was an error
     */
    public boolean isJmxEnabled() throws TaskomaticApiException {
        return (Boolean) invoke("tasko.isJmxEnabled");
    }

    /**
     * Schedule one root ca certificate update
     *
     * @param issRoleIn server role: one of HUB, PERIPHERAL
     * @param fqdn fully qualified domain name of the server
     * @param rootCaCertContent root ca certificate actual content
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSingleRootCaCertUpdate(IssRole issRoleIn, String fqdn, String rootCaCertContent)
            throws TaskomaticApiException {
        String filename = CertificateUtils.computeRootCaFileName(issRoleIn.getLabel(), fqdn);
        scheduleSingleRootCaCertUpdate(filename, rootCaCertContent);
    }

    /**
     * Schedule one root ca certificate update
     *
     * @param fileName          filename of the ca certificate
     * @param rootCaCertContent root ca certificate actual content
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSingleRootCaCertUpdate(String fileName, String rootCaCertContent)
            throws TaskomaticApiException {
        scheduleMultipleRootCaCertUpdate(singletonMap(fileName, rootCaCertContent));
    }

    /**
     * Schedule multiple root ca certificates update.
     *
     * @param filenameToRootCaCertMap maps filename to root ca certificate actual content
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleMultipleRootCaCertUpdate(Map<String, String> filenameToRootCaCertMap)
            throws TaskomaticApiException {

        if ((null == filenameToRootCaCertMap) || filenameToRootCaCertMap.isEmpty()) {
            return; // nothing to do: avoid invoke call, to spare a potential exception
        }

        //sanitise map keys and values: only valid [filename, content] pairs are considered
        Map<String, String> sanitisedFilenameToRootCaCertMap = filenameToRootCaCertMap.entrySet()
                .stream()
                .filter(p -> StringUtils.isNotEmpty(p.getKey()))
                .filter(p -> StringUtils.isNotEmpty(p.getValue()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        if (sanitisedFilenameToRootCaCertMap.isEmpty()) {
            return; // nothing to do: avoid invoke call, to spare a potential exception
        }

        Map<String, Object> paramList = new HashMap<>();
        paramList.put("filename_to_root_ca_cert_map", sanitisedFilenameToRootCaCertMap);
        invoke(SCHEDULE_SINGLE_SAT_BUNCH_RUN, "root-ca-cert-update-bunch", paramList);
    }


    /**
     * Schedule one root ca certificate delete
     *
     * @param issRoleIn server role: one of HUB, PERIPHERAL
     * @param fqdn fully qualified domain name of the server
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSingleRootCaCertDelete(IssRole issRoleIn, String fqdn)
            throws TaskomaticApiException {
        String filename = CertificateUtils.computeRootCaFileName(issRoleIn.getLabel(), fqdn);
        scheduleSingleRootCaCertDelete(filename);
    }

    /**
     * Schedule one root ca certificate delete
     *
     * @param fileName          filename of the ca certificate
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSingleRootCaCertDelete(String fileName)
            throws TaskomaticApiException {
        scheduleMultipleRootCaCertDelete(List.of(fileName));
    }

    /**
     * Schedule multiple root ca certificates delete.
     *
     * @param rootCaCertFilenameList maps filename to root ca certificate actual content
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleMultipleRootCaCertDelete(List<String> rootCaCertFilenameList)
            throws TaskomaticApiException {

        if ((null == rootCaCertFilenameList) || rootCaCertFilenameList.isEmpty()) {
            return; // nothing to do: avoid invoke call, to spare a potential exception
        }

        // empty rootCa content deletes caCert file
        Map<String, String> filenameToRootCaCertMap = rootCaCertFilenameList
                .stream()
                .filter(StringUtils::isNotEmpty)
                .collect(Collectors.toMap(Function.identity(), p -> ""));

        if (filenameToRootCaCertMap.isEmpty()) {
            return; // nothing to do: avoid invoke call, to spare a potential exception
        }

        Map<String, Object> paramList = new HashMap<>();
        paramList.put("filename_to_root_ca_cert_map", filenameToRootCaCertMap);
        invoke(SCHEDULE_SINGLE_SAT_BUNCH_RUN, "root-ca-cert-update-bunch", paramList);
    }

    /**
     * Schedule an import of a GPG key.
     * @param gpgKey the GPG key (armored text)
     * @throws TaskomaticApiException if there was an error
     */
    public void scheduleSingleGpgKeyImport(String gpgKey) throws TaskomaticApiException {
        if (StringUtils.isBlank(gpgKey)) {
            return;
        }
        invoke(SCHEDULE_SINGLE_SAT_BUNCH_RUN, "custom-gpg-key-import-bunch", Map.of("gpg-key", gpgKey));
    }

    /**
     * Schedule a product refresh via taskomatic
     * @param earliest earliest execution
     * @param withReposync perform also a repo-sync
     * @throws TaskomaticApiException if there is an error
     */
    public void scheduleProductRefresh(Date earliest, boolean withReposync) throws TaskomaticApiException {
        invoke(SCHEDULE_SINGLE_SAT_BUNCH_RUN, "mgr-sync-refresh-bunch",
                Map.of("noRepoSync", !withReposync), earliest);
    }
}
