/*
 * Copyright (c) 2009--2012 Red Hat, Inc.
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
package com.redhat.rhn.frontend.action.systems.test;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redhat.rhn.common.util.DatePicker;
import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.test.ChannelFactoryTest;
import com.redhat.rhn.domain.errata.Errata;
import com.redhat.rhn.domain.errata.ErrataFactory;
import com.redhat.rhn.domain.errata.test.ErrataFactoryTest;
import com.redhat.rhn.domain.rhnset.RhnSet;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.server.test.ServerFactoryTest;
import com.redhat.rhn.domain.user.UserFactory;
import com.redhat.rhn.frontend.context.Context;
import com.redhat.rhn.manager.errata.ErrataManager;
import com.redhat.rhn.manager.rhnset.RhnSetDecl;
import com.redhat.rhn.manager.rhnset.RhnSetManager;
import com.redhat.rhn.taskomatic.TaskomaticApi;
import com.redhat.rhn.testing.RhnPostMockStrutsTestCase;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.TimeZone;

/**
 * ErrataConfirmActionTest
 */
public class ErrataConfirmActionTest extends RhnPostMockStrutsTestCase {

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        setRequestPathInfo("/systems/details/ErrataConfirm");

        TaskomaticApi tapi = new TaskomaticApi() {
            @Override
            public void scheduleMinionActionExecutions(List<Action> actions, boolean forcePackageListRefresh) {
                // do nothing for test
            }
        };
        ErrataManager.setTaskomaticApi(tapi);
    }

    /**
     * Tests a good/clean operation, errata are present.
     *
     * @throws Exception something bad happened
     */
    @Test
    public void testExecuteConfirmed() throws Exception {
        Context ctx = Context.getCurrentContext();
        // DatePicker widget needs Context.getTimezone to return a non-null value
        // By default, Context will return a null timezone.
        ctx.setTimezone(TimeZone.getDefault());

        addDispatchCall("errataconfirm.jsp.confirm");

        addRequestParameter(DatePicker.SCHEDULE_TYPE, DatePicker.ScheduleType.DATE.asString());
        // Create System
        Server server = ServerFactoryTest.createTestServer(user, true);

        RhnSet errata = RhnSetDecl.ERRATA.createCustom(
                                        server.getId()).get(user);

        //Fully create channels so that errata can be added to them.

        Channel channel = ChannelFactoryTest.createTestChannel(user);

        // Create a set of Errata IDs
        for (int i = 0; i < 5; i++) {
            Errata e = ErrataFactoryTest.createTestErrata(user.getOrg().getId());
            e.addChannel(channel);
            ErrataFactory.save(e);
            errata.addElement(e.getId());
            ErrataFactoryTest.updateNeedsErrataCache(
                    e.getPackages().iterator().next().getId(),
                    server.getId(), e.getId());
            UserFactory.save(user);
        }
        RhnSetManager.store(errata); //save the set
        addRequestParameter("allowVendorChange", new String("false"));

        addRequestParameter("sid", server.getId().toString());
        addSubmitted();
        // Execute the Action
        actionPerform();
        String forward = getActualForward();
        assertTrue(forward.contains("details/ErrataList"));
    }

    /**
     * Tests when an incomplete set of errata is passed into the action.
     * @throws Exception something bad happened
     */
    @Test
    public void testExecuteIncomplete() throws Exception {

        Context ctx = Context.getCurrentContext();
        // DatePicker widget needs Context.getTimezone to return a non-null value
        // By default, Context will return a null timezone.
        ctx.setTimezone(TimeZone.getDefault());


        addRequestParameter("all", "false");
        RhnSet errata = RhnSetDecl.ERRATA.get(user);
        // Create System
        Server server = ServerFactoryTest.createTestServer(user, true);

        //Fully create channels so that errata can be added to them.
        ChannelFactoryTest.createTestChannel(user);


        RhnSetManager.store(errata); //save the set

        addRequestParameter("sid", server.getId().toString());

        addSubmitted();

        addRequestParameter("allowVendorChange", new String("false"));
        addRequestParameter("dispatch", "dispatch");
        // Execute the Action
        actionPerform();
        assertTrue(getActualForward().contains("systems/errataconfirm.jsp"));
    }

}
