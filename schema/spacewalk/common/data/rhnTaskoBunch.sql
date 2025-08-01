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


INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'daily-status-bunch', 'Sends daily report', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'sat-sync-bunch', 'Runs satellite-sync
Parameters:
- list parameter lists channels
- channel parameter specifies channel to be synced
- without parameter runs satellite-sync without parameters', 'Y');

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'clear-taskologs-bunch', 'Clears taskomatic run log history
Parameters:
- days parameter specifies age of logs to be kept
- without parameter default value will be used', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'cobbler-sync-bunch', 'Applies any cobbler configuration changes', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'compare-configs-bunch', 'Schedules a comparison of config files on all systems', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'session-cleanup-bunch', 'Deletes expired rows from the PXTSessions table to keep it from growing too large', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'sandbox-cleanup-bunch', 'Clean up sandbox', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'repo-sync-bunch', 'Used for syncing repos to a channel', 'Y');

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'package-cleanup-bunch', 'Cleans up orphaned packages', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'kickstartfile-sync-bunch', 'Syncs kickstart profiles that were generated using the wizard', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'kickstart-cleanup-bunch', 'Cleans up stale Kickstarts', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'errata-queue-bunch', 'Processes errata', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'errata-cache-bunch', 'Performs errata cache recalc for a given server or channel', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'channel-repodata-bunch', 'Generates channel repodata', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'cleanup-data-bunch', 'Cleans up orphaned and outdated data', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'ssh-service-bunch', 'Provide services for salt ssh clients', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'cve-server-channels-bunch', 'Generate data required for performing CVE audit queries', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'reboot-action-cleanup-bunch', 'invalidate reboot actions which never finish', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'mgr-sync-refresh-bunch', 'Refresh data about channels, products and subscriptions', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'auto-errata-bunch', 'Schedule automatic errata update actions', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'gatherer-matcher-bunch', 'Schedule running gatherer', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'uuid-cleanup-bunch', 'purge orphaned uuid records', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'minion-action-cleanup-bunch', 'Cleanup actions for Minions', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
             VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'token-cleanup-bunch', 'Cleanup expired channel tokens', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
   VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'minion-action-executor-bunch', 'Execute actions on Minions', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
   VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'minion-action-chain-executor-bunch', 'Execute action chains on Minions', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
   VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'notifications-cleanup-bunch', 'Cleanup expired notification messages', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
   VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'minion-checkin-bunch', 'Perform a regular check-in on minions', null);

INSERT INTO RhnTaskoBunch (id, name, description, org_bunch)
   VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'recurring-action-executor-bunch', 'Schedules actions for minion/group/org', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
   VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'ssh-minion-action-executor-bunch', 'Execute actions on SSH Minions', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
   VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'mgr-forward-registration-bunch', 'Forward registrations to SUSE Customer Center', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'update-payg-data-bunch', 'Runs update-payg-data
Parameters:
- integer parameter payg instance ID
- without parameter updates data for all instances', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
   VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'mgr-update-reporting-bunch', 'Update Reporting DB with current data', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'mgr-update-reporting-hub-bunch', 'Update Reporting DB with data from other susemanager servers', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'system-overview-update-queue-bunch', 'Process system overview update requests', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'update-system-overview-bunch', 'Update the DB table gathering the systems data to show in lists', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'system-profile-refresh-bunch', 'Refresh System Profiles of all registered servers', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'payg-dimension-computation-bunch', 'Compute the dimensions data required for PAYG billing', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'oval-data-sync-bunch', 'Generate OVAL data required to increase the accuracy of CVE audit queries.', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'root-ca-cert-update-bunch', 'Updates root ca certificates', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'custom-gpg-key-import-bunch', 'Import a customer GPG key into the keyring', null);

INSERT INTO rhnTaskoBunch (id, name, description, org_bunch)
VALUES (sequence_nextval('rhn_tasko_bunch_id_seq'), 'errata-advisory-map-sync-bunch', 'Update SUSE errata advisory map to retrieve announcement ids and advisor URLs.', null);

commit;
