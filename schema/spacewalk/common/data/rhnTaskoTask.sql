--
-- Copyright (c) 2010--2016 Red Hat, Inc.
--
-- This software is licensed to you under the GNU General Public License,
-- version 2 (GPLv2). There is NO WARRANTY for this software, express or
-- implied, including the implied warranties of MERCHANTABILITY or FITNESS
-- FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
-- along with this software; if not, see
-- http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
--
-- Red Hat trademarks are not licensed under GPLv2. No permission is
-- granted to use or replicate Red Hat trademarks that are incorporated
-- in this software or its documentation.
--


INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'repo-sync', 'com.redhat.rhn.taskomatic.task.RepoSyncTask');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'ubuntu-errata', 'com.redhat.rhn.taskomatic.task.UbuntuErrataTask');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'satellite-sync', 'com.redhat.rhn.taskomatic.task.SatSyncTask');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'kickstartfile-sync', 'com.redhat.rhn.taskomatic.task.KickstartFileSyncTask');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'kickstart-cleanup', 'com.redhat.rhn.taskomatic.task.KickstartCleanup');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'errata-cache', 'com.redhat.rhn.taskomatic.task.ErrataCacheTask');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'errata-queue', 'com.redhat.rhn.taskomatic.task.ErrataQueue');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'errata-mailer', 'com.redhat.rhn.taskomatic.task.ErrataMailer');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'sandbox-cleanup', 'com.redhat.rhn.taskomatic.task.SandboxCleanup');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'session-cleanup', 'com.redhat.rhn.taskomatic.task.SessionCleanup');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'channel-repodata', 'com.redhat.rhn.taskomatic.task.ChannelRepodata');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'package-cleanup', 'com.redhat.rhn.taskomatic.task.PackageCleanup');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'cobbler-sync', 'com.redhat.rhn.taskomatic.task.CobblerSyncTask');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'daily-summary', 'com.redhat.rhn.taskomatic.task.DailySummary');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'summary-population', 'com.redhat.rhn.taskomatic.task.SummaryPopulation');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'compare-config-files', 'com.redhat.rhn.taskomatic.task.CompareConfigFilesTask');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'clear-log-history', 'com.redhat.rhn.taskomatic.task.ClearLogHistory');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'cleanup-packagechangelog-data', 'com.redhat.rhn.taskomatic.task.ChangeLogCleanUp');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'ssh-service', 'com.redhat.rhn.taskomatic.task.SSHService');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'cve-server-channels', 'com.redhat.rhn.taskomatic.task.CVEServerChannels');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'reboot-action-cleanup', 'com.redhat.rhn.taskomatic.task.RebootActionCleanup');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'mgr-sync-refresh', 'com.redhat.rhn.taskomatic.task.MgrSyncRefresh');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'auto-errata', 'com.redhat.rhn.taskomatic.task.AutoErrataTask');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'gatherer', 'com.redhat.rhn.taskomatic.task.gatherer.GathererJob');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'matcher', 'com.redhat.rhn.taskomatic.task.matcher.MatcherJob');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'uuid-cleanup', 'com.redhat.rhn.taskomatic.task.UuidCleanup');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'minion-action-cleanup', 'com.redhat.rhn.taskomatic.task.MinionActionCleanup');

INSERT INTO rhnTaskoTask (id, name, class)
         VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'token-cleanup', 'com.redhat.rhn.taskomatic.task.TokenCleanup');

INSERT INTO rhnTaskoTask (id, name, class)
   VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'minion-action-executor', 'com.redhat.rhn.taskomatic.task.MinionActionExecutor');

INSERT INTO rhnTaskoTask (id, name, class)
   VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'minion-action-chain-executor', 'com.redhat.rhn.taskomatic.task.MinionActionChainExecutor');

INSERT INTO rhnTaskoTask (id, name, class)
   VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'notifications-cleanup', 'com.redhat.rhn.taskomatic.task.NotificationsCleanup');

INSERT INTO rhnTaskoTask (id, name, class)
   VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'minion-checkin', 'com.redhat.rhn.taskomatic.task.MinionCheckin');

INSERT INTO rhnTaskoTask (id, name, class)
   VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'recurring-action-executor', 'com.redhat.rhn.taskomatic.task.RecurringActionJob');

INSERT INTO rhnTaskoTask (id, name, class)
   VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'ssh-minion-action-executor', 'com.redhat.rhn.taskomatic.task.SSHMinionActionExecutor');

INSERT INTO rhnTaskoTask (id, name, class)
   VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'channel-modular-data-cleanup', 'com.redhat.rhn.taskomatic.task.ModularDataCleanup');

INSERT INTO rhnTaskoTask (id, name, class)
   VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'mgr-forward-registration', 'com.redhat.rhn.taskomatic.task.ForwardRegistrationTask');

INSERT INTO rhnTaskoTask (id, name, class)
VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'update-payg-auth', 'com.redhat.rhn.taskomatic.task.payg.PaygUpdateAuthTask');

INSERT INTO rhnTaskoTask (id, name, class)
VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'update-payg-hosts', 'com.redhat.rhn.taskomatic.task.payg.PaygUpdateHostsTask');

INSERT INTO rhnTaskoTask (id, name, class)
   VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'mgr-update-reporting', 'com.redhat.rhn.taskomatic.task.ReportDbUpdateTask');

INSERT INTO rhnTaskoTask (id, name, class)
VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'mgr-update-reporting-hub', 'com.redhat.rhn.taskomatic.task.HubReportDbUpdateTask');

INSERT INTO rhnTaskoTask (id, name, class)
VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'update-system-overview', 'com.redhat.rhn.taskomatic.task.SystemOverviewUpdateTask');

INSERT INTO rhnTaskoTask (id, name, class)
VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'system-overview-update-queue', 'com.redhat.rhn.taskomatic.task.SystemOverviewUpdateQueue');

INSERT INTO rhnTaskoTask (id, name, class)
VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'system-profile-refresh', 'com.redhat.rhn.taskomatic.task.SystemProfileRefreshTask');

INSERT INTO rhnTaskoTask (id, name, class)
VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'payg-dimension-computation', 'com.redhat.rhn.taskomatic.task.payg.PaygComputeDimensionsTask');

INSERT INTO rhnTaskoTask (id, name, class)
VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'oval-data-sync', 'com.redhat.rhn.taskomatic.task.OVALDataSync');

INSERT INTO rhnTaskoTask (id, name, class)
VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'root-ca-cert-update', 'com.redhat.rhn.taskomatic.task.RootCaCertUpdateTask');

INSERT INTO rhnTaskoTask (id, name, class)
VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'custom-gpg-key-import', 'com.redhat.rhn.taskomatic.task.GpgImportTask');

INSERT INTO rhnTaskoTask (id, name, class)
VALUES (sequence_nextval('rhn_tasko_task_id_seq'), 'errata-advisory-map-sync', 'com.redhat.rhn.taskomatic.task.ErrataAdvisoryMapSync');

commit;
