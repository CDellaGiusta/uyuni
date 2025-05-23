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
package com.redhat.rhn.domain.token.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redhat.rhn.common.hibernate.HibernateFactory;
import com.redhat.rhn.domain.access.AccessGroupFactory;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.test.ChannelFactoryTest;
import com.redhat.rhn.domain.config.ConfigChannel;
import com.redhat.rhn.domain.config.ConfigChannelListProcessor;
import com.redhat.rhn.domain.config.ConfigChannelType;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.server.ServerConstants;
import com.redhat.rhn.domain.server.ServerFactory;
import com.redhat.rhn.domain.server.test.ServerFactoryTest;
import com.redhat.rhn.domain.token.Token;
import com.redhat.rhn.domain.token.TokenFactory;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.testing.ConfigTestUtils;
import com.redhat.rhn.testing.RhnBaseTestCase;
import com.redhat.rhn.testing.TestUtils;
import com.redhat.rhn.testing.UserTestUtils;

import org.hibernate.Session;
import org.hibernate.type.StandardBasicTypes;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * TokenTest
 */
public class TokenTest extends RhnBaseTestCase {

    /**
     * Simple test to check Token creation and the equals method.
     * @throws Exception something bad happened
     */
    @Test
    public void testEquals() throws Exception {
        Token token1 = createTestToken();
        Token token2 = new Token();

        assertNotEquals(token1, token2);

        Session session = HibernateFactory.getSession();
        token2 = (Token) session.getNamedQuery("Token.findById")
                                   .setParameter("id", token1.getId(), StandardBasicTypes.LONG)
                                   .uniqueResult();

        assertEquals(token1, token2);
        assertFalse(token1.isTokenDisabled());
        token1.disable();
        assertTrue(token1.isTokenDisabled());
        assertEquals(1, token1.getEntitlements().size());
        assertEquals(token1.getEntitlements().size(), token2.getEntitlements().size());
    }

    @Test
    public void testLookupByServer() throws Exception {
        Token t = createTestToken();
        Server s = t.getServer();
        flushAndEvict(t);
        assertNotNull(TokenFactory.listByServer(s));
    }

    @Test
    public void testRemoveToken() throws Exception {
        Token t = createTestToken();
        Long id = t.getId();
        TokenFactory.removeToken(t);
        flushAndEvict(t);
        assertNull(TokenFactory.lookupById(id));
    }

    @Test
    public void testChannel() throws Exception {
        Token t = createTestToken();
        Channel c = ChannelFactoryTest.createTestChannel(t.getCreator());
        t.addChannel(c);
        TokenFactory.save(t);
        t = (Token) reload(t);
        assertNotNull(t.getChannels());
        assertEquals(1, t.getChannels().size());

    }

    @Test
    public void testConfigChannels() throws Exception {
        Token t = createTestToken();
        User user = UserTestUtils.createUser("testuser1", t.getOrg().getId());
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);

        // Create a global channel
        ConfigChannel global1 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        ConfigChannel global2 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());

        ConfigChannelListProcessor proc = new ConfigChannelListProcessor();

        proc.add(t.getConfigChannelsFor(user), global1);
        proc.add(t.getConfigChannelsFor(user), global2);

        TokenFactory.save(t);
        List ls = new ArrayList<>();
        ls.add(global1);
        ls.add(global2);

        t = (Token) reload(t);
        assertNotNull(t.getConfigChannelsFor(user));
        assertEquals(2, t.getConfigChannelsFor(user).size());
        assertEquals(ls, t.getConfigChannelsFor(user));
    }

    /**
     * Helper method to create a test Token
     * @return Returns a Token
     * @throws Exception something bad happened
     */
    public static Token createTestToken() throws Exception {
        Token token = new Token();
        token.enable();
        token.setDeployConfigs(true);
        token.setNote("RHN-JAVA test note");
        token.setUsageLimit(42L);
        User user = UserTestUtils.createUser("testuser",
                                             UserTestUtils.createOrg("testorg"));
        token.setCreator(user);
        token.setOrg(user.getOrg());
        token.setServer(ServerFactoryTest.createTestServer(user));
        token.setContactMethod(ServerFactory.findContactMethodById(0L));

        token.addEntitlement(ServerConstants.getServerGroupTypeEnterpriseEntitled());

        assertNull(token.getId());
        TestUtils.saveAndFlush(token);
        assertNotNull(token.getId());

        return token;
    }
}
