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
package com.redhat.rhn.domain.action.config.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.action.ActionFactory;
import com.redhat.rhn.domain.action.config.ConfigAction;
import com.redhat.rhn.domain.action.config.ConfigDeployAction;
import com.redhat.rhn.domain.action.config.ConfigDiffAction;
import com.redhat.rhn.domain.action.config.ConfigVerifyAction;
import com.redhat.rhn.domain.action.test.ActionFactoryTest;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.testing.RhnBaseTestCase;
import com.redhat.rhn.testing.UserTestUtils;

import org.junit.jupiter.api.Test;

/**
 * ConfigActionTest
 */
public class ConfigActionTest extends RhnBaseTestCase {

    @Test
    public void testCreate() throws Exception {
        User usr = UserTestUtils.findNewUser("testUser",
                "testOrg" + this.getClass().getSimpleName());

        ConfigAction testAction = (ConfigAction)ActionFactoryTest.createAction(usr,
                ActionFactory.TYPE_CONFIGFILES_DEPLOY);
        ConfigRevisionActionTest.createTestRevision(usr, testAction);
        ActionFactory.save(testAction);
        flushAndEvict(testAction);
        /*
         * Get action back out of db and make sure it committed correctly
         */
        Action same = ActionFactory.lookupById(testAction.getId());
        assertInstanceOf(ConfigAction.class, same);
        ConfigAction sameAction = (ConfigAction) same;

        assertNotNull(sameAction.getConfigRevisionActions());
        assertEquals(sameAction.getConfigRevisionActions().size(), 2);
        assertNotNull(sameAction.getConfigRevisionActions().toArray()[0]);
        assertNotNull(sameAction.getConfigRevisionActions().toArray()[1]);
        assertEquals(sameAction.getName(), testAction.getName());
        assertEquals(sameAction.getId(), testAction.getId());
    }

    @Test
    public void testCreateConfigDeployAction() throws Exception {
        User user = UserTestUtils.createUser("testUser", UserTestUtils
                .createOrg("testOrg" + this.getClass().getSimpleName()));
        Action a = ActionFactoryTest.createAction(user,
                ActionFactory.TYPE_CONFIGFILES_DEPLOY);

        assertNotNull(a);
        assertInstanceOf(ConfigAction.class, a);
        assertInstanceOf(ConfigDeployAction.class, a);
        assertNotNull(a.getActionType());
    }

    @Test
    public void testCreateConfigVerifyAction() throws Exception {
        User user = UserTestUtils.createUser("testUser", UserTestUtils
                .createOrg("testOrg" + this.getClass().getSimpleName()));
        Action a = ActionFactoryTest.createAction(user,
                ActionFactory.TYPE_CONFIGFILES_VERIFY);

        assertNotNull(a);
        assertInstanceOf(ConfigAction.class, a);
        assertInstanceOf(ConfigVerifyAction.class, a);
        assertNotNull(a.getActionType());
    }

    @Test
    public void testCreateConfigDiffAction() throws Exception {
        User user = UserTestUtils.createUser("testUser", UserTestUtils
                .createOrg("testOrg" + this.getClass().getSimpleName()));
        Action a = ActionFactoryTest.createAction(user,
                ActionFactory.TYPE_CONFIGFILES_DIFF);

        assertNotNull(a);
        assertInstanceOf(ConfigAction.class, a);
        assertInstanceOf(ConfigDiffAction.class, a);
        assertNotNull(a.getActionType());
    }

}
