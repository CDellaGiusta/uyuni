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


INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='daily-status-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='summary-population'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                         (SELECT id FROM rhnTaskoBunch WHERE name='daily-status-bunch'),
                         (SELECT id FROM rhnTaskoTask WHERE name='daily-summary'),
                         1,
                         'FINISHED');

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='sat-sync-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='satellite-sync'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='clear-taskologs-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='clear-log-history'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='cobbler-sync-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='cobbler-sync'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='compare-configs-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='compare-config-files'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='session-cleanup-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='session-cleanup'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='sandbox-cleanup-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='sandbox-cleanup'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='repo-sync-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='repo-sync'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='repo-sync-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='ubuntu-errata'),
                        1,
                        'FINISHED');

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='package-cleanup-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='package-cleanup'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='kickstartfile-sync-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='kickstartfile-sync'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='kickstart-cleanup-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='kickstart-cleanup'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='errata-queue-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='errata-queue'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='channel-repodata-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='channel-repodata'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='errata-cache-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='errata-cache'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='errata-cache-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='errata-mailer'),
                        1,
                        'FINISHED');

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='cleanup-data-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='cleanup-packagechangelog-data'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='reboot-action-cleanup-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='reboot-action-cleanup'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='ssh-service-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='ssh-service'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='cve-server-channels-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='cve-server-channels'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='auto-errata-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='auto-errata'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='mgr-sync-refresh-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='mgr-sync-refresh'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='gatherer-matcher-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='gatherer'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='gatherer-matcher-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='matcher'),
                        1,
                        'FINISHED');

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='uuid-cleanup-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='uuid-cleanup'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='minion-action-cleanup-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='minion-action-cleanup'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='token-cleanup-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='token-cleanup'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='minion-action-executor-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='minion-action-executor'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='minion-action-chain-executor-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='minion-action-chain-executor'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='notifications-cleanup-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='notifications-cleanup'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='minion-checkin-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='minion-checkin'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='recurring-action-executor-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='recurring-action-executor'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='ssh-minion-action-executor-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='ssh-minion-action-executor'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='cleanup-data-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='channel-modular-data-cleanup'),
                        1,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='mgr-forward-registration-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='mgr-forward-registration'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name = 'update-payg-data-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name = 'update-payg-auth'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name = 'update-payg-data-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name = 'update-payg-hosts'),
                        1,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                        (SELECT id FROM rhnTaskoBunch WHERE name='mgr-update-reporting-bunch'),
                        (SELECT id FROM rhnTaskoTask WHERE name='mgr-update-reporting'),
                        0,
                        null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                    (SELECT id FROM rhnTaskoBunch WHERE name='mgr-update-reporting-hub-bunch'),
                    (SELECT id FROM rhnTaskoTask WHERE name='mgr-update-reporting-hub'),
                    0,
                    null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                    (SELECT id FROM rhnTaskoBunch WHERE name='update-system-overview-bunch'),
                    (SELECT id FROM rhnTaskoTask WHERE name='update-system-overview'),
                    0,
                    null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                    (SELECT id FROM rhnTaskoBunch WHERE name='system-overview-update-queue-bunch'),
                    (SELECT id FROM rhnTaskoTask WHERE name='system-overview-update-queue'),
                    0,
                    null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                    (SELECT id FROM rhnTaskoBunch WHERE name='system-profile-refresh-bunch'),
                    (SELECT id FROM rhnTaskoTask WHERE name='system-profile-refresh'),
                    0,
                    null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                    (SELECT id FROM rhnTaskoBunch WHERE name='payg-dimension-computation-bunch'),
                    (SELECT id FROM rhnTaskoTask WHERE name='payg-dimension-computation'),
                    0,
                    null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                    (SELECT id FROM rhnTaskoBunch WHERE name = 'oval-data-sync-bunch'),
                    (SELECT id FROM rhnTaskoTask WHERE name = 'oval-data-sync'),
                    0,
                    null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                    (SELECT id FROM rhnTaskoBunch WHERE name='root-ca-cert-update-bunch'),
                    (SELECT id FROM rhnTaskoTask WHERE name='root-ca-cert-update'),
                    0,
                    null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
             VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                    (SELECT id FROM rhnTaskoBunch WHERE name='custom-gpg-key-import-bunch'),
                    (SELECT id FROM rhnTaskoTask WHERE name='custom-gpg-key-import'),
                    0,
                    null);

INSERT INTO rhnTaskoTemplate (id, bunch_id, task_id, ordering, start_if)
            VALUES (sequence_nextval('rhn_tasko_template_id_seq'),
                    (SELECT id FROM rhnTaskoBunch WHERE name = 'errata-advisory-map-sync-bunch'),
                    (SELECT id FROM rhnTaskoTask WHERE name = 'errata-advisory-map-sync'),
                    0,
                    null);

commit;
