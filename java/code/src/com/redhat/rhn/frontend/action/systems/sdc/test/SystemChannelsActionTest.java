/*
 * Copyright (c) 2009--2010 Red Hat, Inc.
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
package com.redhat.rhn.frontend.action.systems.sdc.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.frontend.action.systems.sdc.SystemChannelsAction;
import com.redhat.rhn.frontend.dto.ChildChannelDto;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.testing.ChannelTestUtils;
import com.redhat.rhn.testing.RhnMockStrutsTestCase;
import com.redhat.rhn.testing.ServerTestUtils;
import com.redhat.rhn.testing.TestUtils;

import org.apache.struts.action.DynaActionForm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * SystemChannelsActionTest
 */
public class SystemChannelsActionTest extends RhnMockStrutsTestCase {

    private Server server;

    /**
     * {@inheritDoc}
     */
    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        server = ServerTestUtils.createTestSystem(user);
        // Create some child channels so we can subscribe to them
        Channel child1 = ChannelTestUtils.createChildChannel(user, server.getBaseChannel());
        child1.setOrg(null);
        Channel child2 = ChannelTestUtils.createChildChannel(user, server.getBaseChannel());
        child2.setOrg(null);

        TestUtils.saveAndFlush(child1);
        TestUtils.saveAndFlush(child2);

        server.addChannel(child2);
        TestUtils.saveAndFlush(server);

        // Org Owned channel
        ChannelTestUtils.createTestChannel(user);

        addRequestParameter(RequestContext.SID, server.getId().toString());
        setRequestPathInfo("/systems/details/SystemChannels");
    }


    @Test
    public void testExecute() {

        actionPerform();
        assertNotNull(request.getAttribute(RequestContext.SYSTEM));
        DynaActionForm form = (DynaActionForm) getActionForm();
        assertNotNull(request.getAttribute(SystemChannelsAction.AVAIL_CHILD_CHANNELS));

        ChildChannelDto[] children = (ChildChannelDto[])
            request.getAttribute(SystemChannelsAction.AVAIL_CHILD_CHANNELS);

        assertEquals(2, children.length);

        boolean found = false;
        for (ChildChannelDto childIn : children) {
            if (childIn.getSubscribed()) {
                found = true;
                break;
            }
        }
        Assertions.assertTrue(found, "Enabled child not found.");

        assertNotNull(request.getAttribute(SystemChannelsAction.BASE_CHANNELS));
        assertNotNull(request.getAttribute(SystemChannelsAction.CUSTOM_BASE_CHANNELS));
        assertNotNull(form.get(SystemChannelsAction.NEW_BASE_CHANNEL_ID));
    }

    @Test
    public void testConfirmUpdateBaseChannel() throws Exception {
        addDispatchCall("sdc.channels.edit.confirm_update_base");
        Channel newBase = ChannelTestUtils.createBaseChannel(user);
        addRequestParameter(SystemChannelsAction.NEW_BASE_CHANNEL_ID,
                newBase.getId().toString());
        actionPerform();
        assertNotNull(request.getAttribute(
                SystemChannelsAction.CURRENT_PRESERVED_CHILD_CHANNELS));
        assertNotNull(request.getAttribute(
                SystemChannelsAction.CURRENT_UNPRESERVED_CHILD_CHANNELS));
        assertNotNull(request.getAttribute(SystemChannelsAction.CURRENT_BASE_CHANNEL));
        assertNotNull(request.getAttribute(SystemChannelsAction.NEW_BASE_CHANNEL));
    }

    @Test
    public void testUpdateBaseChannel() throws Exception {
        addDispatchCall("sdc.channels.confirmNewBase.modifyBaseSoftwareChannel");
        Channel newBase = ChannelTestUtils.createBaseChannel(user);
        addRequestParameter(SystemChannelsAction.NEW_BASE_CHANNEL_ID,
                newBase.getId().toString());
        actionPerform();
        server = TestUtils.reload(server);
        assertEquals(newBase.getId(), server.getBaseChannel().getId());
        verifyActionMessages(new String[]{"sdc.channels.edit.base_channel_updated",
                "sdc.channels.edit.deploy.warning"});
    }

    @Test
    public void testUpdateNoBaseChannel() {
        addDispatchCall("sdc.channels.confirmNewBase.modifyBaseSoftwareChannel");
        addRequestParameter(SystemChannelsAction.NEW_BASE_CHANNEL_ID, "-1");
        actionPerform();
        server = TestUtils.reload(server);
        assertNull(server.getBaseChannel());
        verifyActionMessages(new String[]{"sdc.channels.edit.base_channel_updated",
                "sdc.channels.edit.deploy.warning"});
    }

    @Test
    public void testUpdateChildChannels() throws Exception {
        addDispatchCall("sdc.channels.edit.update_sub");

        Channel child1 = ChannelTestUtils.createChildChannel(user, server.getBaseChannel());
        Channel child2 = ChannelTestUtils.createChildChannel(user, server.getBaseChannel());
        Channel child3 = ChannelTestUtils.createChildChannel(user, server.getBaseChannel());

        String[] childchan = new String[2];
        childchan[0] = child1.getId().toString();
        childchan[1] = child2.getId().toString();
        addRequestParameter(SystemChannelsAction.CHILD_CHANNELS, childchan);
        actionPerform();
        server = TestUtils.reload(server);
        assertTrue(TestUtils.
                arraySearch(server.getChannels().toArray(), "getId", child1.getId()));
        assertTrue(TestUtils.
                arraySearch(server.getChannels().toArray(), "getId", child2.getId()));
        assertFalse(TestUtils.
                arraySearch(server.getChannels().toArray(), "getId", child3.getId()));
        verifyActionMessages(new String[]{"sdc.channels.edit.child_channels_updated",
                "sdc.channels.edit.deploy.warning"});
    }
}

