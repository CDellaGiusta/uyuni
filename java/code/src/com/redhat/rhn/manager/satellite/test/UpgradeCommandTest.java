/*
 * Copyright (c) 2009--2013 Red Hat, Inc.
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
package com.redhat.rhn.manager.satellite.test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redhat.rhn.domain.kickstart.KickstartData;
import com.redhat.rhn.domain.kickstart.KickstartFactory;
import com.redhat.rhn.domain.kickstart.KickstartSession;
import com.redhat.rhn.domain.task.Task;
import com.redhat.rhn.domain.task.TaskFactory;
import com.redhat.rhn.frontend.action.kickstart.test.KickstartTestHelper;
import com.redhat.rhn.manager.satellite.UpgradeCommand;
import com.redhat.rhn.testing.BaseTestCaseWithUser;

import org.junit.jupiter.api.Test;

import java.util.List;

public class UpgradeCommandTest extends BaseTestCaseWithUser {

    @Test
    public void testUpgradeProfiles() throws Exception {
        TaskFactory.createTask(user.getOrg(), UpgradeCommand.UPGRADE_KS_PROFILES, 0L);
        List<Task> l = TaskFactory.getTaskListByNameLike(UpgradeCommand.UPGRADE_KS_PROFILES);
        assertInstanceOf(Task.class, l.get(0));

        KickstartData ksd = KickstartTestHelper.createTestKickStart(user);

        KickstartSession ksession =
            KickstartFactory.lookupDefaultKickstartSessionForKickstartData(ksd);
        assertNull(ksession);

        // UpgradeCommand its its own transaction so we gotta commit.
        commitAndCloseSession();
        commitHappened();

        UpgradeCommand cmd = new UpgradeCommand();
        cmd.upgrade();

        // Check to see if the upgrade command created the default profile.
        ksession =
            KickstartFactory.lookupDefaultKickstartSessionForKickstartData(ksd);
        assertNotNull(ksession);

        List<Task> tasks = TaskFactory.getTaskListByNameLike(UpgradeCommand.UPGRADE_KS_PROFILES);
        assertTrue((tasks == null || tasks.isEmpty()));
    }
}
