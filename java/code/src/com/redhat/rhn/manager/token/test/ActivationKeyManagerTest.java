/*
 * Copyright (c) 2009--2014 Red Hat, Inc.
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
package com.redhat.rhn.manager.token.test;

import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.redhat.rhn.domain.access.AccessGroupFactory;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.config.ConfigChannel;
import com.redhat.rhn.domain.config.ConfigChannelListProcessor;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.server.test.ServerFactoryTest;
import com.redhat.rhn.domain.token.ActivationKey;
import com.redhat.rhn.domain.token.ActivationKeyFactory;
import com.redhat.rhn.domain.token.Token;
import com.redhat.rhn.domain.token.TokenChannelAppStream;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.xmlrpc.DuplicateAppStreamException;
import com.redhat.rhn.manager.token.ActivationKeyManager;
import com.redhat.rhn.testing.BaseTestCaseWithUser;
import com.redhat.rhn.testing.ChannelTestUtils;
import com.redhat.rhn.testing.ConfigTestUtils;
import com.redhat.rhn.testing.TestUtils;
import com.redhat.rhn.testing.UserTestUtils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;


/**
 * ActivationKeyManagerTest
 */
public class ActivationKeyManagerTest extends BaseTestCaseWithUser {
    private ActivationKeyManager manager;

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        manager = ActivationKeyManager.getInstance();
    }
    @Test
    public void testDelete() {
        user.addToGroup(AccessGroupFactory.ACTIVATION_KEY_ADMIN);
        ActivationKey key = manager.createNewActivationKey(user, "Test");
        ActivationKey temp = manager.lookupByKey(key.getKey(), user);
        assertNotNull(temp);
        manager.remove(temp, user);
        try {
            manager.lookupByKey(key.getKey(), user);
            String msg = "NUll lookup failed, because this object should exist!";
            fail(msg);
        }
        catch (Exception e) {
         // great!.. Exception for null lookpu is controvoersial but convenient..
        }
    }
    @Test
    public void testDeployConfig() throws Exception {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.ACTIVATION_KEY_ADMIN);

        //need a tools channel for config deploy
        Channel base = ChannelTestUtils.createBaseChannel(user);
        ChannelTestUtils.setupBaseChannelForVirtualization(user, base);

        ActivationKey key = createActivationKey();
        //Create a config channel
        ConfigChannel cc = ConfigTestUtils.createConfigChannel(user.getOrg());
        ConfigChannelListProcessor proc = new ConfigChannelListProcessor();
        proc.add(key.getConfigChannelsFor(user), cc);
        key.setDeployConfigs(true);
        ActivationKeyFactory.save(key);
        assertTrue(key.getDeployConfigs());
        assertFalse(key.getChannels().isEmpty());
    }
    @Test
    public void testConfigPermissions() throws Exception {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.ACTIVATION_KEY_ADMIN);
        ActivationKey key = createActivationKey();

        //need a tools channel for config deploy
        Channel base = ChannelTestUtils.createBaseChannel(user);
        ChannelTestUtils.setupBaseChannelForVirtualization(user, base);

        key.setDeployConfigs(true);
        //Create a config channel
        ConfigChannel cc = ConfigTestUtils.createConfigChannel(user.getOrg());
        ConfigChannelListProcessor proc = new ConfigChannelListProcessor();
        proc.add(key.getConfigChannelsFor(user), cc);
        ActivationKeyFactory.save(key);
        assertTrue(key.getDeployConfigs());
        assertFalse(key.getChannels().isEmpty());
        assertTrue(key.getConfigChannelsFor(user).contains(cc));
    }

    @Test
    public void testLookup() {
        //first lets just check on permissions...
        user.addToGroup(AccessGroupFactory.ACTIVATION_KEY_ADMIN);
        final ActivationKey key = manager.createNewActivationKey(user, "Test");
        ActivationKey temp;
        //we make newuser
        // unfortunately satellite is NOT multiorg aware...
        //So we can't check on the org clause
        //so...
        User newUser = UserTestUtils.findNewUser("testUser2",
                "testOrg" + this.getClass().getSimpleName());
        try {
            manager.lookupByKey(key.getKey(), newUser);
            String msg = "Permission check failed :(.." +
                            "Activation key should not have gotten found out" +
                         " because the user does not have activation key admin role";

            fail(msg);
        }
        catch (Exception e) {
            // great!.. Exception for permission failure always welcome
        }
        try {
            manager.lookupByKey(key.getKey() + "FOFOFOFOFOFOF", user);
            String msg = "NUll lookup failed, because this object should NOT exist!";
            fail(msg);
        }
        catch (Exception e) {
         // great!.. Exception for null lookpu is controvoersial but convenient..
        }
        temp = manager.lookupByKey(key.getKey(), user);
        assertNotNull(temp);
        assertEquals(user.getOrg(), temp.getOrg());
    }

    @Test
    public void testCreatePermissions() {
        ActivationKey key;
        //test permissions
        try {
            manager.createNewActivationKey(user,  "Test");
            String msg = "Permission check failed :(.." +
                            "Activation key should not have gotten created" +
                            " because the user does not have activation key admin role";
            fail(msg);
        }
        catch (Exception e) {
            // great!.. Exception for permission failure always welcome
        }

        //test permissions
        try {
            String keyName = "I_RULE_THE_WORLD";
            Long usageLimit = 1200L;
            Channel baseChannel = ChannelTestUtils.createBaseChannel(user);
            String note = "Test";
            manager.createNewActivationKey(user,
                                                    keyName, note, usageLimit,
                                                    baseChannel, true);

            String msg = "Permission check failed :(.." +
                            "Activation key should not have gotten created" +
                            " becasue the user does not have activation key admin role";
            fail(msg);
        }
        catch (Exception e) {
            // great!.. Exception for permission failure always welcome
        }

    }

    @Test
    public void testCreate() throws Exception {
        user.addToGroup(AccessGroupFactory.ACTIVATION_KEY_ADMIN);
        String note = "Test";
        final ActivationKey key = manager.createNewActivationKey(user, note);
        assertEquals(user.getOrg(), key.getOrg());
        assertEquals(note, key.getNote());
        assertNotNull(key.getKey());
        Server server = ServerFactoryTest.createTestServer(user, true);

        final ActivationKey key1 = manager.createNewReActivationKey(user, server, note);
        assertEquals(server, key1.getServer());

        ActivationKey temp = manager.lookupByKey(key.getKey(), user);
        assertNotNull(temp);
        assertEquals(user.getOrg(), temp.getOrg());
        assertEquals(note, temp.getNote());

        String keyName = "I_RULE_THE_WORLD";
        Long usageLimit = 1200L;
        Channel baseChannel = ChannelTestUtils.createBaseChannel(user);

        final ActivationKey key2 = manager.createNewReActivationKey(user, server,
                                                keyName, note, usageLimit,
                                                baseChannel, true, null);


        temp = (ActivationKey)reload(key2);
        assertTrue(temp.getKey().endsWith(keyName));
        assertEquals(note, temp.getNote());
        assertEquals(usageLimit, temp.getUsageLimit());
        Set channels = new HashSet<>();
        channels.add(baseChannel);
        assertEquals(channels, temp.getChannels());

        //since universal default == true we have to
        // check if the user org has it..
        Token token = user.getOrg().getToken();
        assertEquals(channels, token.getChannels());
        assertEquals(usageLimit, token.getUsageLimit());
    }

    @Test
    public void testHasAppStreamModuleEnabled() throws Exception {
        ActivationKey key = createActivationKey();
        Channel channel = ChannelTestUtils.createBaseChannel(user);
        key.getAppStreams().add(
            new TokenChannelAppStream(key.getToken(), channel, "ruby:3.3")
        );

        assertTrue(manager.hasAppStreamModuleEnabled(key, channel, "ruby", "3.3"));
        assertFalse(manager.hasAppStreamModuleEnabled(key, channel, "ruby", "3.2"));
        assertFalse(manager.hasAppStreamModuleEnabled(key, channel, "nginx", "3.3"));
    }

    @Test
    public void testSaveChannelAppStreams() throws Exception {
        ActivationKey key = createActivationKey();
        Channel channel = ChannelTestUtils.createBaseChannel(user);

        List<String> toInclude = List.of("php:8.1", "nginx:1.24");
        List<String> toRemove = List.of();

        manager.saveChannelAppStreams(key, channel, toInclude, toRemove);

        assertTrue(key.getAppStreams().stream().anyMatch(appStream -> appStream.getAppStream().equals("php:8.1")));
        assertTrue(key.getAppStreams().stream().anyMatch(appStream -> appStream.getAppStream().equals("nginx:1.24")));

        assertThrows(DuplicateAppStreamException.class, () ->
            manager.saveChannelAppStreams(key, channel, List.of("php:8.2"), List.of())
        );

        toInclude = List.of("php:8.2");
        toRemove = List.of("php:8.1");
        manager.saveChannelAppStreams(key, channel, toInclude, toRemove);
        assertFalse(key.getAppStreams().stream().anyMatch(appStream -> appStream.getAppStream().equals("php:8.1")));
        assertTrue(key.getAppStreams().stream().anyMatch(appStream -> appStream.getAppStream().equals("php:8.2")));
    }

    @Test
    public void testRemoveAppStreams() throws Exception {
        ActivationKey key = createActivationKey();
        Channel channel = ChannelTestUtils.createBaseChannel(user);

        key.getAppStreams().add(new TokenChannelAppStream(key.getToken(), channel, "nodejs:18"));
        key.getAppStreams().add(new TokenChannelAppStream(key.getToken(), channel, "mariadb:10.11"));

        List<String> toRemove = List.of("mariadb:10.11");

        manager.removeAppStreams(key, toRemove);

        assertFalse(key.getAppStreams().stream()
                .anyMatch(appStream -> appStream.getAppStream().equals("mariadb:10.11")));
        assertTrue(key.getAppStreams().stream()
                .anyMatch(appStream -> appStream.getAppStream().equals("nodejs:18")));
    }

    public ActivationKey createActivationKey() {
        user.addToGroup(AccessGroupFactory.ACTIVATION_KEY_ADMIN);
        return  manager.createNewActivationKey(user, TestUtils.randomString());
    }

    @Test
    public void testFindAll() {
        ActivationKeyFactory.createNewKey(user, null, "ak- " + TestUtils.randomString(),
                "", 1L, null, true);

        List<ActivationKey> activationKeys =
                ActivationKeyManager.getInstance().findAll(user);
        assertEquals(1, activationKeys.size());
    }
}
