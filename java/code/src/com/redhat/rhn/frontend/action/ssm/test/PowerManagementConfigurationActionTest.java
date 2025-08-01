/*
 * Copyright (c) 2013 SUSE LLC
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
package com.redhat.rhn.frontend.action.ssm.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.action.kickstart.PowerManagementAction;
import com.redhat.rhn.frontend.action.kickstart.test.PowerManagementActionTest;
import com.redhat.rhn.manager.kickstart.cobbler.CobblerXMLRPCHelper;
import com.redhat.rhn.testing.RhnMockStrutsTestCase;
import com.redhat.rhn.testing.ServerTestUtils;

import org.cobbler.CobblerConnection;
import org.cobbler.SystemRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedList;
import java.util.List;

import servletunit.HttpServletRequestSimulator;

/**
 * Tests PowerManagementConfigurationAction
 * @author Silvio Moioli {@literal <smoioli@suse.de>}
 */
public class PowerManagementConfigurationActionTest extends RhnMockStrutsTestCase {
    private CobblerConnection connection;
    private List<Server> servers;

    /**
     * Sets up a request.
     * @throws Exception if things go wrong
     * @see com.redhat.rhn.testing.RhnMockStrutsTestCase#setUp()
     */
    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        connection = CobblerXMLRPCHelper.getConnection(user.getLogin());
        servers = setUpTestProvisionableSsmServers(user);
    }

    /**
     * Sets up a list of servers with provisioning entitlement and adds them to
     * the SSM for test purposes.
     * @param user the current user
     * @return the list of server
     * @throws Exception if something goes wrong
     */
    public static List<Server> setUpTestProvisionableSsmServers(User user)
            throws Exception {
        List<Server> result = new LinkedList<>();
        for (int i = 0; i < 2; i++) {
            Server server = ServerTestUtils.createTestSystem(user);
            result.add(server);
            ServerTestUtils.addServersToSsm(user, server.getId());
        }
        return result;
    }

    /**
     * Tests creating Cobbler system records with a chosen profile from SSM.
     */
    @Test
    public void testExecute() {
        setRequestPathInfo("/systems/ssm/provisioning/PowerManagementConfiguration");
        request.setMethod(HttpServletRequestSimulator.POST);

        addSubmitted();
        addDispatchCall("ssm.provisioning.powermanagement.configuration.update");
        request.addParameter(PowerManagementAction.POWER_TYPE,
            PowerManagementActionTest.EXPECTED_TYPE);
        request.addParameter(PowerManagementAction.POWER_ADDRESS,
            PowerManagementActionTest.EXPECTED_ADDRESS);
        request.addParameter(PowerManagementAction.POWER_USERNAME,
            PowerManagementActionTest.EXPECTED_USERNAME);
        request.addParameter(PowerManagementAction.POWER_PASSWORD,
            PowerManagementActionTest.EXPECTED_PASSWORD);
        request.addParameter(PowerManagementAction.POWER_ID,
            PowerManagementActionTest.EXPECTED_ID);
        actionPerform();

        for (Server server : servers) {
            SystemRecord systemRecord = SystemRecord
                .lookupById(connection, server.getCobblerId());
            assertEquals(PowerManagementActionTest.EXPECTED_TYPE, systemRecord.getPowerType());
            assertEquals(PowerManagementActionTest.EXPECTED_ADDRESS,
                    systemRecord.getPowerAddress());
            assertEquals(PowerManagementActionTest.EXPECTED_USERNAME,
                    systemRecord.getPowerUsername());
            assertEquals(PowerManagementActionTest.EXPECTED_PASSWORD,
                    systemRecord.getPowerPassword());
            assertEquals(PowerManagementActionTest.EXPECTED_ID, systemRecord.getPowerId());
        }

        // In SSM empty string means "do not change"
        request.addParameter(PowerManagementAction.POWER_TYPE,
                PowerManagementActionTest.EXPECTED_TYPE);
        request.addParameter(PowerManagementAction.POWER_ADDRESS, "");
        request.addParameter(PowerManagementAction.POWER_USERNAME,
                PowerManagementActionTest.EXPECTED_USERNAME_2);
        request.addParameter(PowerManagementAction.POWER_PASSWORD,
                PowerManagementActionTest.EXPECTED_PASSWORD_2);
        request.addParameter(PowerManagementAction.POWER_ID, "");
        actionPerform();

        for (Server server : servers) {
            SystemRecord systemRecord = SystemRecord
                .lookupById(connection, server.getCobblerId());
            assertEquals(PowerManagementActionTest.EXPECTED_TYPE, systemRecord.getPowerType());
            assertEquals(PowerManagementActionTest.EXPECTED_ADDRESS,
                    systemRecord.getPowerAddress());
            assertEquals(PowerManagementActionTest.EXPECTED_USERNAME_2,
                    systemRecord.getPowerUsername());
            assertEquals(PowerManagementActionTest.EXPECTED_PASSWORD_2,
                    systemRecord.getPowerPassword());
            assertEquals(PowerManagementActionTest.EXPECTED_ID, systemRecord.getPowerId());
        }
    }
}
