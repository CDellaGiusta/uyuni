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
package com.redhat.rhn.manager.configuration.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.redhat.rhn.common.db.datasource.DataResult;
import com.redhat.rhn.domain.access.AccessGroupFactory;
import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.action.ActionFactory;
import com.redhat.rhn.domain.action.config.ConfigAction;
import com.redhat.rhn.domain.action.config.ConfigRevisionAction;
import com.redhat.rhn.domain.config.ConfigChannel;
import com.redhat.rhn.domain.config.ConfigChannelListProcessor;
import com.redhat.rhn.domain.config.ConfigChannelType;
import com.redhat.rhn.domain.config.ConfigFile;
import com.redhat.rhn.domain.config.ConfigFileCount;
import com.redhat.rhn.domain.config.ConfigFileState;
import com.redhat.rhn.domain.config.ConfigFileType;
import com.redhat.rhn.domain.config.ConfigRevision;
import com.redhat.rhn.domain.config.ConfigurationFactory;
import com.redhat.rhn.domain.org.OrgFactory;
import com.redhat.rhn.domain.rhnset.RhnSet;
import com.redhat.rhn.domain.role.RoleFactory;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.server.ServerConstants;
import com.redhat.rhn.domain.server.ServerFactory;
import com.redhat.rhn.domain.server.test.MinionServerFactoryTest;
import com.redhat.rhn.domain.server.test.ServerFactoryTest;
import com.redhat.rhn.domain.token.ActivationKey;
import com.redhat.rhn.domain.token.ActivationKeyFactory;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.domain.user.UserFactory;
import com.redhat.rhn.frontend.dto.ConfigChannelDto;
import com.redhat.rhn.frontend.dto.ConfigFileDto;
import com.redhat.rhn.frontend.dto.ConfigFileNameDto;
import com.redhat.rhn.frontend.dto.ConfigGlobalDeployDto;
import com.redhat.rhn.frontend.dto.ConfigSystemDto;
import com.redhat.rhn.frontend.dto.LastDeployDto;
import com.redhat.rhn.frontend.dto.ScheduledAction;
import com.redhat.rhn.frontend.listview.PageControl;
import com.redhat.rhn.manager.action.ActionManager;
import com.redhat.rhn.manager.configuration.ConfigurationManager;
import com.redhat.rhn.manager.rhnset.RhnSetDecl;
import com.redhat.rhn.manager.rhnset.RhnSetManager;
import com.redhat.rhn.manager.system.SystemManager;
import com.redhat.rhn.manager.system.test.SystemManagerTest;
import com.redhat.rhn.manager.token.ActivationKeyManager;
import com.redhat.rhn.taskomatic.TaskomaticApi;
import com.redhat.rhn.testing.BaseTestCaseWithUser;
import com.redhat.rhn.testing.ConfigTestUtils;
import com.redhat.rhn.testing.ServerTestUtils;
import com.redhat.rhn.testing.TestUtils;
import com.redhat.rhn.testing.UserTestUtils;

import org.apache.commons.lang3.RandomUtils;
import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.imposters.ByteBuddyClassImposteriser;
import org.jmock.junit5.JUnit5Mockery;
import org.jmock.lib.concurrent.Synchroniser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.stream.LongStream;

@ExtendWith(JUnit5Mockery.class)
public class ConfigurationManagerTest extends BaseTestCaseWithUser {

    private User user;
    private PageControl pc;
    private ConfigurationManager cm;
    private static final ConfigFileCount EXPECTED_COUNT =
                                    ConfigFileCount.create(3, 0, 1, 0);

    @RegisterExtension
    protected final Mockery context = new JUnit5Mockery() {{
        setThreadingPolicy(new Synchroniser());
    }};

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        //Create a user and an org
        user = UserTestUtils.findNewUser("testyman", "orgman");
        pc = new PageControl();
        pc.setStart(1);
        pc.setPageSize(20);
        cm = ConfigurationManager.getInstance();
        context.setImposteriser(ByteBuddyClassImposteriser.INSTANCE);
    }

    @Override
    @AfterEach
    public void tearDown() throws Exception {
        user = null;
        pc = null;
        cm = null;
        super.tearDown();
    }

    @Test
    public void testListSystemsForFileCopy() throws Exception {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);

        // Create a system
        Server srv1 = ServerFactoryTest.createTestServer(user, true,
                ServerConstants.getServerGroupTypeEnterpriseEntitled());
        Server minion = MinionServerFactoryTest.createTestMinionServer(user);

        // Create a local for that system
        ConfigChannel local = srv1.getLocalOverride();

        // Create a sandbox for that system
        ConfigChannel sandbox = srv1.getSandboxOverride();

        // Create a global channel
        ConfigChannel global = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        // Susbscribe system to global
        srv1.subscribeConfigChannel(global, user);
        ServerFactory.save(srv1);

        // Create files one, two, and three in global
        final String[] paths = {"/etc/foo1", "/etc/foo2", "/etc/foo3"};

        Long[] cfnids = new Long[3];
        ConfigFile file;

        for (int i = 0; i < paths.length; i++) {
            file = global.createConfigFile(
                    ConfigFileState.normal(), paths[i]);
            cfnids[i] = file.getConfigFileName().getId();
            ConfigTestUtils.createConfigRevision(file);
        }
        ConfigurationFactory.commit(global);

        // Create file two in system-local
        file = local.createConfigFile(
                ConfigFileState.normal(), paths[1]);
        ConfigTestUtils.createConfigRevision(file);
        ConfigurationFactory.commit(local);

        // Create file three in system-sandbox
        file = sandbox.createConfigFile(
                ConfigFileState.normal(), paths[2]);
        ConfigTestUtils.createConfigRevision(file);
        ConfigurationFactory.commit(sandbox);

        // Ask for listSystemsForFileCopy(f1, local) - expect 1 sys, 0 rev
        DataResult<ConfigSystemDto> dr = ConfigurationManager.getInstance().
            listSystemsForFileCopy(user,
                    cfnids[0], ConfigChannelType.local(), null);
        assertNotNull(dr);

        // make sure we don't get any minion back in the list because this is not supported
        assertFalse(dr.stream().flatMapToLong(id -> LongStream.of(((ConfigSystemDto) id).getId()))
                .anyMatch(id->id == minion.getId()));

        Map<String, Object> elabParams = new HashMap<>();
        elabParams.put("cfnid", cfnids[0]);
        elabParams.put("label", ConfigChannelType.local().getLabel());
        dr.elaborate(elabParams);

        assertEquals(1, dr.size());
        assertNull(dr.get(0).getConfigRevisionId());

        // Ask for listSystemsForFileCopy(f2, local) - expect 1 sys, 1 rev
        dr = ConfigurationManager.getInstance().
            listSystemsForFileCopy(user,
                cfnids[1], ConfigChannelType.local(), null);

        assertNotNull(dr);
        elabParams = new HashMap<>();
        elabParams.put("cfnid", cfnids[1]);
        elabParams.put("label", ConfigChannelType.local().getLabel());
        dr.elaborate(elabParams);
        assertEquals(1, dr.size());
        assertNotNull(dr.get(0).getConfigRevisionId());

        // Ask for listSystemsForFileCopy(f3, local) - expect 1 sys, 0 rev
        dr = ConfigurationManager.getInstance().
            listSystemsForFileCopy(user,
                cfnids[2], ConfigChannelType.local(), null);
        assertNotNull(dr);
        elabParams = new HashMap<>();
        elabParams.put("cfnid", cfnids[2]);
        elabParams.put("label", ConfigChannelType.local().getLabel());
        dr.elaborate(elabParams);
        assertEquals(1, dr.size());
        assertNull(dr.get(0).getConfigRevisionId());

        // Ask for listSystemsForFileCopy(f3, sandbox) - expect 1 sys, 1 rev
        dr = ConfigurationManager.getInstance().
            listSystemsForFileCopy(user,
                cfnids[2], ConfigChannelType.sandbox(), null);
        assertNotNull(dr);
        elabParams = new HashMap<>();
        elabParams.put("cfnid", cfnids[2]);
        elabParams.put("label",
                ConfigChannelType.sandbox().getLabel());
        dr.elaborate(elabParams);
        assertEquals(1, dr.size());
        assertNotNull(dr.get(0).getConfigRevisionId());
    }

    @Test
    public void testListCurrentFiles() {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);

        // Channel of interest - has rev-1 of aFile
        ConfigChannel gcc1 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        ConfigFile theFile = gcc1.createConfigFile(
                ConfigFileState.normal(), "/etc/foo1");
        ConfigTestUtils.createConfigRevision(theFile);
        theFile = gcc1.createConfigFile(
                ConfigFileState.normal(), "/etc/foo2");
        ConfigTestUtils.createConfigRevision(theFile);
        ConfigurationFactory.commit(gcc1);
        DataResult<ConfigFileDto> dr = ConfigurationManager.getInstance().
            listCurrentFiles(user, gcc1, null);
        assertNotNull(dr);
        assertEquals(2, dr.getTotalSize());

        RhnSet theSet = RhnSetDecl.CONFIG_CHANNEL_DEPLOY_REVISIONS.create(user);
        theSet.addElement(theFile.getId());
        RhnSetManager.store(theSet);
        dr = ConfigurationManager.getInstance().
        listCurrentFiles(user, gcc1, null,
                RhnSetDecl.CONFIG_CHANNEL_DEPLOY_REVISIONS.getLabel(), false);
        assertNotNull(dr);
        assertEquals(1, dr.getTotalSize());
    }

    /**
     * Tests listing files of a state config channel.
     */
    @Test
    public void testListCurrentFilesSlsCase() {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);

        ConfigChannel configChannel = ConfigTestUtils.createConfigChannel(user.getOrg(), ConfigChannelType.state());

        // create config files
        ConfigFile initSls = configChannel.createConfigFile(ConfigFileState.normal(), "/init.sls");
        ConfigRevision configRevision = ConfigTestUtils.createConfigRevision(initSls);
        configRevision.setConfigFileType(ConfigFileType.sls());

        ConfigFile normalFile = configChannel.createConfigFile(ConfigFileState.normal(), "/my/foo2.sls");
        ConfigRevision configRevision1 = ConfigTestUtils.createConfigRevision(normalFile);
        configRevision1.setConfigFileType(ConfigFileType.sls());

        ConfigurationFactory.commit(configChannel);

        // init.sls should not be listed
        DataResult<ConfigFileDto> dr = ConfigurationManager.getInstance().listCurrentFiles(user, configChannel, null);
        assertEquals(1, dr.getTotalSize());

        // init.sls should not be listed
        dr = ConfigurationManager.getInstance().listCurrentFiles(user, configChannel, null, null, false);
        assertEquals(1, dr.getTotalSize());

        // includeInitSls is explicitly true, init.sls should be listed
        dr = ConfigurationManager.getInstance().listCurrentFiles(user, configChannel, null, null, true);
        assertEquals(2, dr.getTotalSize());
    }

    @Test
    public void testGlobalFileDeployInfo() throws Exception {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);

        // Channel of interest - has rev-1 of aFile
        ConfigChannel gcc1 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        ConfigFile theFile = gcc1.createConfigFile(
                ConfigFileState.normal(), "/etc/foo");
        ConfigTestUtils.createConfigRevision(theFile);
        ConfigurationFactory.commit(gcc1);

        // Other global channel 1 - has rev-2 of aFile
        ConfigChannel gcc2 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        ConfigFile aFile = gcc2.createConfigFile(
                ConfigFileState.normal(), "/etc/foo");
        ConfigTestUtils.createConfigRevision(aFile);
        ConfigurationFactory.commit(gcc2);

        // Other global channel 2 - has rev-3 of aFile
        ConfigChannel gcc3 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        aFile = gcc3.createConfigFile(ConfigFileState.normal(),
            "/etc/foo");
        ConfigTestUtils.createConfigRevision(aFile);
        ConfigurationFactory.commit(gcc3);

        // System-2 local channel - has rev-4 of aFile
        ConfigChannel local2 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.local());
        aFile = local2.createConfigFile(ConfigFileState.normal(),
            "/etc/foo");
        ConfigTestUtils.createConfigRevision(aFile);
        ConfigurationFactory.commit(local2);

        // System-4 local channel - has rev-5 of aFile
        ConfigChannel local4 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.local());
        aFile = local4.createConfigFile(ConfigFileState.normal(),
                "/etc/foo");
        ConfigTestUtils.createConfigRevision(aFile);
        ConfigurationFactory.commit(local4);

        Long ver = 2L;
        // System 1 - no outranks, no overrides
        Server srv1 = ServerFactoryTest.createTestServer(user, true);

        SystemManagerTest.giveCapability(srv1.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);
        srv1.subscribeConfigChannel(gcc1, user);
        ServerFactory.save(srv1);

        // System 2 - no outranks, an override
        Server srv2 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv2.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);
        srv2.subscribeConfigChannel(gcc1, user);
        srv2.setLocalOverride(local2);
        ServerFactory.save(srv2);

        // System 3 - 1 outrank, no override
        Server srv3 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv3.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);
        srv3.subscribeConfigChannel(gcc2, user);
        srv3.subscribeConfigChannel(gcc1, user);
        ServerFactory.save(srv3);

        // System 4 - 1 outrank, an override
        Server srv4 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv4.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);
        srv4.subscribeConfigChannel(gcc2, user);
        srv4.subscribeConfigChannel(gcc1, user);
        srv4.setLocalOverride(local4);
        ServerFactory.save(srv4);

        // System 5 - 2 outranks, no override
        Server srv5 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv5.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);
        srv5.subscribeConfigChannel(gcc3, user);
        srv5.subscribeConfigChannel(gcc2, user);
        srv5.subscribeConfigChannel(gcc1, user);
        ServerFactory.save(srv5);

        DataResult dr = ConfigurationManager.getInstance().
            listGlobalFileDeployInfo(user, gcc1, theFile, null);

        assertNotNull(dr);
        assertEquals(5, dr.getTotalSize());

        Map<String, Object> params = new HashMap<>();
        params.put("ccid", gcc1.getId());
        params.put("cfnid", theFile.getConfigFileName().getId());
        dr.elaborate(params);

        for (int i = 0; i < dr.getTotalSize(); i++) {
            ConfigGlobalDeployDto dto = (ConfigGlobalDeployDto)dr.get(i);
            assertNotNull(dto);
            if (dto.getId().longValue() == srv1.getId().longValue()) {
                assertEquals(srv1.getName(), dto.getName());
                assertEquals(srv1, dto.getServer());
                assertEquals(0, dto.getOutrankedCount().intValue());
                assertEquals(0, dto.getOverrideCount().intValue());
            }
            else if (dto.getId().longValue() == srv2.getId().longValue()) {
                assertEquals(srv2.getName(), dto.getName());
                assertEquals(srv2, dto.getServer());
                assertEquals(0, dto.getOutrankedCount().intValue());
                assertEquals(1, dto.getOverrideCount().intValue());
            }
            else if (dto.getId().longValue() == srv3.getId().longValue()) {
                assertEquals(srv3.getName(), dto.getName());
                assertEquals(srv3, dto.getServer());
                assertEquals(1, dto.getOutrankedCount().intValue());
                assertEquals(0, dto.getOverrideCount().intValue());
            }
            else if (dto.getId().longValue() == srv4.getId().longValue()) {
                assertEquals(srv4.getName(), dto.getName());
                assertEquals(srv4, dto.getServer());
                assertEquals(1, dto.getOutrankedCount().intValue());
                assertEquals(1, dto.getOverrideCount().intValue());
            }
            else if (dto.getId().longValue() == srv5.getId().longValue()) {
                assertEquals(srv5.getName(), dto.getName());
                assertEquals(srv5, dto.getServer());
                assertEquals(2, dto.getOutrankedCount().intValue());
                assertEquals(0, dto.getOverrideCount().intValue());
            }
            else {
                fail("DTO for UNKNOWN SERVER ID [" + dto.getId() + "]");
            }
        }

    }

    @Test
    public void testListGlobalChannels() throws Exception {
        //Create a config channel
        ConfigChannel cc = ConfigTestUtils.createConfigChannel(user.getOrg());

        /* We now have to associate the user and config channel so that the user has access
         * There are two ways to do this:
         *   1. Make the user a config admin (or org admin)
         *   2. Subscribe a system visible to that user to the config channel
         * I am going with option #2 because I think its a better test.
         */
        ConfigTestUtils.giveUserChanAccess(user, cc);  //option 2
        //UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);  //option 1

        DataResult dr = cm.listGlobalChannels(user, pc);
        assertEquals(1, dr.getTotalSize());
        assertInstanceOf(ConfigChannelDto.class, dr.get(0));
        assertEquals(1, ((ConfigChannelDto)dr.get(0)).getSystemCount().intValue());
    }

    @Test
    public void testListGlobalChannelsForSDC() {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);

        //Create a config channel
        ConfigChannel cc = ConfigTestUtils.createConfigChannel(user.getOrg());
        Server srv = ServerFactoryTest.createTestServer(user, true);
        ServerFactory.save(srv);
        DataResult<ConfigChannelDto> dr = cm.
                        listGlobalChannelsForSystemSubscriptions(srv, user, pc);

        assertTrue(contains(cc, dr));

        srv.subscribeConfigChannel(cc, user);
        ServerFactory.save(srv);

        dr = cm.listGlobalChannelsForSystemSubscriptions(srv, user, pc);
        assertFalse(contains(cc, dr));
    }

    @Test
    public void testListGlobalChannelsForActivationKeys() {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.ACTIVATION_KEY_ADMIN);

        //Create a config channel
        ConfigChannel cc = ConfigTestUtils.createConfigChannel(user.getOrg());
        ActivationKeyManager akManager = ActivationKeyManager.getInstance();
        ActivationKey key = akManager.createNewActivationKey(user, "Test");

        DataResult<ConfigChannelDto> subscriptions = cm.
                        listGlobalChannelsForActivationKeySubscriptions(key, user);
        assertTrue(contains(cc, subscriptions));
        assertFalse(subscriptions.get(0).getCanAccess());
        DataResult<ConfigChannelDto> current = cm.
                                        listGlobalChannelsForActivationKey(key, user);
        assertFalse(contains(cc, current));
        ConfigChannelListProcessor proc = new ConfigChannelListProcessor();
        proc.add(key.getConfigChannelsFor(user), cc);
        ActivationKeyFactory.save(key);

        subscriptions = cm.listGlobalChannelsForActivationKeySubscriptions(key, user);
        assertFalse(contains(cc, subscriptions));
        current = cm.listGlobalChannelsForActivationKey(key, user);
        assertTrue(contains(cc, current));
        assertFalse(current.get(0).getCanAccess());
    }

    /**
     * Checks if a given config channel is present in a list.
     * @param cc Config channel
     * @param list list of type COnfigChannelDto
     * @return true if the List contains it , false other wise
     */
    private boolean contains(ConfigChannel cc, List<ConfigChannelDto> list) {
        for (ConfigChannelDto dto : list) {
            if (dto.getLabel().equals(cc.getLabel())) {
                return true;
            }
        }
        return false;
    }

    @Test
    public void testListManagedSystemsAndFiles() throws Exception {
        //Create a config file, along with a config channel
        ConfigFile cf = ConfigTestUtils.createConfigFile(user.getOrg());
        ConfigurationFactory.commit(cf);

        //Simple checks to see that everything committed alright
        assertTrue(cf.getId() > 0);
        assertNotNull(cf.getConfigChannel());
        assertTrue(cf.getConfigChannel().getId() > 0);

        //Only Config Admins can use this manager function.
        //Making the user a config admin will also automatically
        //give him access to the file and channel we just created.
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);

        //That is not enough though, the user must also have a server that is
        //a member of the config channel and have access to the server as well.
        Server s = ServerFactoryTest.createTestServer(user, true);

        s.subscribeConfigChannel(cf.getConfigChannel(), user);
        ConfigTestUtils.giveConfigCapabilities(s);
        //Call the function we are testing
        DataResult<ConfigSystemDto> dr = cm.listManagedSystemsAndFiles(user, pc);

        //Make sure we got what we expected.
        assertEquals(1, dr.getTotalSize());
        assertNotNull(dr.get(0));
        assertEquals(1, dr.get(0).getConfigChannelCount().intValue());
        assertEquals(1, dr.get(0).getGlobalFileCount().intValue());
    }

    @Test
    public void testListGlobalConfigFiles() throws Exception {
        //Create a config file,  and a config channel
        ConfigFile cf = ConfigTestUtils.createConfigFile(user.getOrg());
        ConfigTestUtils.createConfigRevision(cf);

        //Give the user access to the channel
        ConfigTestUtils.giveUserChanAccess(user, cf.getConfigChannel());

        //Call the function we are testing
        DataResult<ConfigFileDto> dr = cm.listGlobalConfigFiles(user, pc);

        //Make sure we got what we expected.
        assertEquals(1, dr.getTotalSize());
        assertNotNull(dr.get(0));
        assertEquals(1, dr.get(0).getSystemCount().intValue());
    }

    @Test
    public void testListLocalConfigFiles() throws Exception {
        //Create a local Config Channel
        ConfigChannel cc = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.local());
        //Create a Config File and put it in this channel
        ConfigFile cf = ConfigTestUtils.createConfigFile(cc);

        //We also need a config revision, because we are going to ask the
        //file for its file type and that information exists for revisions,
        //but not files.
        ConfigTestUtils.createConfigRevision(cf);

        /*
         * This is a tad weird, but we have to give the user a server that she has
         * access to, and we have to subscribe that server to this local channel.
         * This is the exact process followed by giving a user access to a channel.
         * The fact that this is a local channel for a single server is irrelevant
         * because all config channels work the same way.
         */
        ConfigTestUtils.giveUserChanAccess(user, cc);

        //Call the function we are testing
        DataResult<ConfigFileDto> dr = cm.listLocalConfigFiles(user, pc);
        assertEquals(1, dr.getTotalSize());
        assertNotNull(dr.get(0));
        assertNotNull(dr.get(0).getServerName());
    }

    @Test
    public void testGetRecentlyModifiedConfigFiles() throws Exception {
        //Create a channel to put files in
        ConfigChannel cc = ConfigTestUtils.createConfigChannel(user.getOrg());

        int numFiles = 3; //the number of files we will create

        //Create the files.
        for (int i = 0; i < numFiles; i++) {
            ConfigFile file = ConfigTestUtils.createConfigFile(cc);

            //We also need a config revision, because we are going to ask the
            //file for its file type and that information exists for revisions,
            //but not files.
            ConfigTestUtils.createConfigRevision(file);
        }

        //Give the user access to the channel and thus the files.
        ConfigTestUtils.giveUserChanAccess(user, cc);

        //Call the function we are testing,  list more than we created to make sure
        //we have only that many.
        DataResult<ConfigFileDto> dr = cm.getRecentlyModifiedConfigFiles(user, numFiles + 5);
        assertEquals(numFiles, dr.getTotalSize());
        assertNotNull(dr.get(0));

        //Now test that limiting the results works as well.
        int numToShow = 2;
        //show only a few of the files.
        dr = cm.getRecentlyModifiedConfigFiles(user, numToShow);
        assertEquals(numToShow, dr.getTotalSize());

        //This last test really doesn't work if we limit more than we create.
        //this is to ensure that if we change those values, the tests are still valid.
        assertTrue(numToShow < numFiles);
    }

    @Test
    public void testGetOverviewSummary() throws Exception {
        //Create a config channel
        ConfigChannel cc = ConfigTestUtils.createConfigChannel(user.getOrg());
        //Subscribe a system to the channel and give access for the channel to the user
        ConfigTestUtils.giveUserChanAccess(user, cc);
        //put a couple files into the channel
        ConfigTestUtils.createConfigFile(cc);
        ConfigTestUtils.createConfigFile(cc);

        //Create a local config channel
        ConfigChannel lcc = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.local());
        /* Create a system and subscribe it to the local channel.
         * It seems a little strange that we are subscribing a system to a local channel,
         * but that's the way things are.
         */
        ConfigTestUtils.giveUserChanAccess(user, lcc);
        //put a file into the local channel
        ConfigTestUtils.createConfigFile(lcc);



        //Call the function we are testing
        Map<String, Long> map = cm.getOverviewSummary(user);

        //First make sure that the map has the right keys.
        assertTrue(map.containsKey("systems"));
        assertTrue(map.containsKey("channels"));
        assertTrue(map.containsKey("global_files"));
        assertTrue(map.containsKey("local_files"));
        //quota does not exist in satellite
        assertFalse(map.containsKey("quota"));

        //Now test the values
        assertEquals(2, map.get("systems").longValue());
        assertEquals(1, map.get("channels").longValue());
        assertEquals(2, map.get("global_files").longValue());
        assertEquals(1, map.get("local_files").longValue());
    }

    /**
     *
     */
    @Test
    public void testAvailableChannels() {
        // Create a system
        Server srv1 = ServerFactoryTest.createTestServer(user, true);

        // Are we guaranteed to find local and sandbox?
        assertNotNull(srv1.getLocalOverride());
        assertNotNull(srv1.getSandboxOverride());

        ConfigurationFactory.commit(srv1.getLocalOverride());
        ConfigurationFactory.commit(srv1.getSandboxOverride());

        // Are local and sandbox guaranteed to NOT show up?
        List channels  = srv1.getConfigChannelList();
        assertNotNull(channels);
        assertEquals(0, channels.size());

        // Create a global channel
        ConfigChannel global = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        // Susbscribe system to global
        srv1.subscribeConfigChannel(global, user);

        // Can we find the global channel?
        channels  = srv1.getConfigChannelList();
        assertEquals(1, channels.size());
    }

    /**
     * 1) Create a central config channel (A) add a bunch of files &amp; dirs
     * 2) Call ConfigurationManager.countCentrallyManagedFiles and verify
     *      that we have the correct answer
     * 3) Create a new channel and add ONE file thats new and One file
     *      duplicate of a file in Channel (A) ...
     * 4) Call ConfigurationManager.countCentrallyManagedFiles and verify
     *      that the answer is number of files in Channel A + 1
     * @throws Exception under exceptional circumstances
     */

    @Test
    public void testCountCentrallyManagedFiles() throws Exception {
        user.getOrg().addRole(RoleFactory.CONFIG_ADMIN);
        user.addToGroup(AccessGroupFactory.CONFIG_ADMIN);
        Server s = makeServerForChannelCountTests();
        ConfigFileCount actual = cm.countCentrallyManagedPaths(s, user);

        assertEquals(EXPECTED_COUNT, actual);

        final ConfigChannel c = s.getConfigChannelStream().findFirst().get();

        SortedSet files = c.getConfigFiles();
        assertEquals(files.size(), EXPECTED_COUNT.getFiles() +
                                        EXPECTED_COUNT.getDirectories());
        //now add a new channel -
        // (with some file/ directory intersections)

        ConfigFile fl = (ConfigFile) files.first();
        final String path = fl.getConfigFileName().getPath();

        ConfigChannel cc = ConfigTestUtils.createConfigChannel(user.getOrg());

        //Create a Duplicate Path and add it to the new channel
        final ConfigFile fl2 = cc.createConfigFile(
                                    ConfigFileState.normal(),
                                    path);
        ConfigTestUtils.createConfigRevision(fl2,
                        ConfigFileType.file());

        //Now Create a NEW Path and add it to the new channel
        ConfigFile fl3 = ConfigTestUtils.createConfigFile(cc);
        ConfigTestUtils.createConfigRevision(fl3,
                                ConfigFileType.file());

        s.subscribeConfigChannel(cc, user);
        ServerFactory.save(s);
        actual = cm.countCentrallyManagedPaths(s, user);

        ConfigFileCount expected = ConfigFileCount.create(
                                                EXPECTED_COUNT.getFiles() + 1, 0,
                                                EXPECTED_COUNT.getDirectories(), 0);
        assertEquals(expected, actual);
    }

    /**
     * 1) Create a central config channel (A) add a bunch of files &amp; dirs
     * 2) Call ConfigurationManager.countCentrallyDeployableFiles and verify
     *      that we have the correct answer
     * 3) Create a Local channel and add One file
     *       duplicate of a file in Channel (A) ...
     * 4) Verify that the NUM_OF_FILES = NUM_OF_FILES - 1
     * 5) Add ONE file thats new to Channel A and store
     * 6) Call ConfigurationManager.countCentrallyManagedFiles and verify
     *      that the answer should be =  number of files previously
     *                  in Channel A before step 5 (ie NUM_OF_FILES)
     *      num_of_centrally_deployable_files(A) =  num_centrally_managed_files (A)
     *                                     - num_of_files( A ^ Local)
     *                   where ^ = Intersection
     *
     *    In the above example
     *      num_of_centrally_deployable_files(A) =  (NUM_OF_FILES + 1) + NUM_OF_DIRS
     *                                                  - 1
     *                                      =  NUM_OF_FILES + NUM_OF_DIRS
     *
     * @throws Exception under exceptional circumstances
     */

    @Test
    public void testCountCentrallyDeployableFiles() throws Exception {
        Server s = makeServerForChannelCountTests();
        ConfigFileCount actual = cm.countCentrallyDeployablePaths(s, user);
        assertEquals(EXPECTED_COUNT, actual);

        //now add a local channel
        // with 1 file intersection & 1 new file
        //
        ConfigChannel local = ConfigTestUtils.createConfigChannel(user.getOrg(),
                                ConfigChannelType.local());


        ConfigChannel c = s.getConfigChannelStream().findFirst().get();
        String path = c.getConfigFiles().first().getConfigFileName().getPath();
        ConfigFile fl = local.createConfigFile(
                                ConfigFileState.normal(),
                                path);
        ConfigTestUtils.createConfigRevision(fl,
                            ConfigFileType.file());

        s.setLocalOverride(local);
        ServerFactory.save(s);
        actual = cm.countCentrallyDeployablePaths(s, user);
        ConfigFileCount expected = ConfigFileCount.create(
                                            EXPECTED_COUNT.getFiles() - 1, 0,
                                            EXPECTED_COUNT.getDirectories(), 0);

        assertEquals(expected, actual);

        //Now Create a NEW Path and add it to the original central channel
        ConfigFile fl3 = ConfigTestUtils.createConfigFile(c);
        ConfigTestUtils.createConfigRevision(fl3,
                            ConfigFileType.file());
        ServerFactory.save(s);

        actual = cm.countCentrallyDeployablePaths(s, user);

        assertEquals(EXPECTED_COUNT, actual);

        ServerFactory.save(s);
    }
    /**
     * Counts the number of locally managed files... for a given server
     * @throws Exception if channel/server creation fails
     */
    @Test
    public void testCountLocallyManagedFiles() throws Exception {
        Server s = makeServerForChannelCountTests();

        ConfigChannel local = ConfigTestUtils.createConfigChannel(user.getOrg(),
                                    ConfigChannelType.local());
        addFilesAndDirs(local);
        s.setLocalOverride(local);
        ServerFactory.save(s);

        ConfigFileCount actual = cm.countLocallyManagedPaths(s, user,
                                        ConfigChannelType.local()
                                    );
        assertEquals(EXPECTED_COUNT, actual);
    }


    private Server makeServerForChannelCountTests() throws Exception {
        ConfigChannel cc = ConfigTestUtils.createConfigChannel(user.getOrg());
        addFilesAndDirs(cc);
        Server s = ConfigTestUtils.giveUserChanAccess(user, cc);
        ServerFactory.save(s);
        s = TestUtils.reload(s);
        return s;
    }

    private void addFilesAndDirs(ConfigChannel cc) {
        for (int i = 0; i < EXPECTED_COUNT.getFiles(); i++) {
            ConfigFile fl = ConfigTestUtils.createConfigFile(cc);
            ConfigTestUtils.createConfigRevision(fl,
                                ConfigFileType.file());
        }

        for (int i = 0; i < EXPECTED_COUNT.getDirectories(); i++) {
            ConfigFile fl = ConfigTestUtils.createConfigFile(cc);
            ConfigTestUtils.createConfigRevision(fl,
                        ConfigFileType.dir());
        }
    }


    @Test
    public void testGetLocalDeploysTo() throws Exception {
        //Create a local config channel
        ConfigChannel lcc = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.local());
        // Create aserver, add to channel, make sure user has access to both
        Server srv = ConfigTestUtils.giveUserChanAccess(user, lcc);

        // Create a config file in the local channel
        ConfigFile file = ConfigTestUtils.createConfigFile(lcc);

        // NOW - look for successful deploys (which should be zero)
        List<LastDeployDto> deploys = cm.getSuccesfulDeploysTo(user,
                                    file.getConfigFileName(), srv);
        assertNotNull(deploys);
        assertEquals(0, deploys.size());
    }

    @Test
    public void testListSystemInfoForChannel() {
        // Create  global config channels
        ConfigChannel gcc1 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        ConfigChannel gcc2 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());

        //Create a local config channel and a server it belongs to
        ConfigChannel lcc = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.local());
        Server srv1 = ServerFactoryTest.createTestServer(user, true);
        srv1.setLocalOverride(lcc);

        // Subscribe to globals
        srv1.subscribeConfigChannel(gcc2, user);
        srv1.subscribeConfigChannel(gcc1, user);

        // Create a second, subscribe to global
        Server srv2 = ServerFactoryTest.createTestServer(user, true);
        srv2.subscribeConfigChannel(gcc1, user);

        ServerFactory.save(srv1);
        ServerFactory.save(srv2);

        // Create some config files in the global channel
        ConfigFile file1 = ConfigTestUtils.createConfigFile(gcc1);
        ConfigTestUtils.createConfigFile(gcc1);

        // Create a similarly-named file in srv1's local channel
        lcc.createConfigFile(ConfigFileState.normal(), file1.getConfigFileName());

        // And a similar file into the higher-priority channel
        gcc2.createConfigFile(ConfigFileState.normal(), file1.getConfigFileName());


        //
        // NOW - first, test the "show me all the systems in the channel" API
        //
        DataResult<ConfigSystemDto> dr = ConfigurationManager.getInstance().listSystemInfoForChannel(user,
                gcc1, null);
        Map<String, Object> elabParams = new HashMap<>();
        elabParams.put("ccid", gcc1.getId());
        dr.elaborate(elabParams);

        assertNotNull(dr);
        assertEquals(2, dr.getTotalSize());
        boolean foundSysOne = false;
        for (int i = 0; i < dr.getTotalSize(); i++) {
            ConfigSystemDto dto = dr.get(i);
            if (dto.getName().equals(srv1.getName())) {
                foundSysOne = true;
                assertEquals(1, dto.getOverriddenCount().intValue());
                assertEquals(1, dto.getOutrankedCount().intValue());
                break;
            }
        }
        assertTrue(foundSysOne);

        // FINALLY - put sys1 into the config-channel-deploy set, and retest using that
        // set-label
        RhnSet theSet = RhnSetDecl.CONFIG_CHANNEL_DEPLOY_SYSTEMS.create(user);
        theSet.addElement(srv1.getId());
        RhnSetManager.store(theSet);
        dr = ConfigurationManager.getInstance().
            listSystemInfoForChannel(user, gcc1, null, true);
        assertNotNull(dr);
        assertEquals(1, dr.getTotalSize());
    }

    @Test
    public void testChannelSubscriptions() throws Exception {
        ConfigChannel cc = ConfigTestUtils.createConfigChannel(user.getOrg());
        Server s = ConfigTestUtils.giveUserChanAccess(user, cc);
        s.subscribeConfigChannel(ConfigTestUtils.createConfigChannel(user.getOrg()), user);
        s.subscribeConfigChannel(ConfigTestUtils.createConfigChannel(user.getOrg()), user);
        ServerFactory.save(s);
        s.unsubscribeConfigChannel(cc, user);
        ServerFactory.save(s);
        s = TestUtils.reload(s);
        assertEquals(2, s.getConfigChannelCount());
    }

    @Test
    public void testFilesNotInChannel() throws Exception {
        // Create two channels
        ConfigChannel cc1 = ConfigTestUtils.createConfigChannel(user.getOrg());
        ConfigTestUtils.giveUserChanAccess(user, cc1);
        addFilesAndDirs(cc1);
        ConfigChannel cc2 = ConfigTestUtils.createConfigChannel(user.getOrg());
        ConfigTestUtils.giveUserChanAccess(user, cc2);
        addFilesAndDirs(cc2);
        ConfigFile file = ConfigTestUtils.createConfigFile(cc2);
        ConfigTestUtils.createConfigRevision(file);

        // cc2 should have 4 files and 1 dir (the not-files)
        DataResult<ConfigFileDto> dr = ConfigurationManager.getInstance().
            listFilesNotInChannel(user, cc1, pc);
        assertEquals(5, dr.getTotalSize());

        // cc1 should now have 3 files and 1 dir (the not-files)
        dr = ConfigurationManager.getInstance().listFilesNotInChannel(user, cc2, pc);
        assertEquals(4, dr.getTotalSize());
    }

    @Test
    public void testListSystemsNotInChannel() throws Exception {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);

        // Create  global config channels
        ConfigChannel gcc1 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        ConfigChannel gcc2 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());

        Long ver = 2L;

        // In 'my' channel
        Server srv1 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv1.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);

        // NOT in 'mt' channel
        Server srv2 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv2.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);
        Server srv3 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv3.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);
        Server srv4 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv4.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);

        // Not in ANY channel, but config-mgt-enabled
        Server srv5 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv5.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);

        // Not in any channel, and NOT config-mgt-enabled
        Server srv6 = ServerFactoryTest.createTestServer(user, true);

        srv1.subscribeConfigChannel(gcc1, user);
        srv2.subscribeConfigChannel(gcc2, user);
        srv3.subscribeConfigChannel(gcc2, user);
        srv4.subscribeConfigChannel(gcc2, user);

        ServerFactory.save(srv1);
        ServerFactory.save(srv2);
        ServerFactory.save(srv3);
        ServerFactory.save(srv4);
        ServerFactory.save(srv5);
        ServerFactory.save(srv6);

        DataResult<ConfigSystemDto> dr = ConfigurationManager.getInstance().
            listChannelSystems(user, gcc1, null);
        assertEquals(1, dr.getTotalSize());

        dr = ConfigurationManager.getInstance().listChannelSystems(user, gcc2, null);
        assertEquals(3, dr.getTotalSize());


        // On Spacewalk, ALL systems belong to one big, happy Org.  So if there are any
        // systems committed, they'll screw up our counts.  Sigh, and move on.
        dr = ConfigurationManager.getInstance().
            listSystemsNotInChannel(user, gcc1, null);
        assertTrue(4 <= dr.getTotalSize());

        dr = ConfigurationManager.getInstance().
            listSystemsNotInChannel(user, gcc2, null);
        assertTrue(2 <= dr.getTotalSize());
    }

    @Test
    public void testDeployConfiguration() throws Exception {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);
        ConfigurationManager mgr = ConfigurationManager.getInstance();

        TaskomaticApi taskomaticMock = context.mock(TaskomaticApi.class);
        ActionManager.setTaskomaticApi(taskomaticMock);

        context.checking(new Expectations() { {
            allowing(taskomaticMock).scheduleActionExecution(with(any(Action.class)));
        } });

        // Create  global config channels
        ConfigChannel gcc1 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        ConfigChannel gcc2 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());

        Long ver = 2L;

        // gcc1 only
        Server srv1 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv1.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);

        srv1.subscribeConfigChannel(gcc1, user);
        srv1.subscribeConfigChannel(gcc2, user);

        ServerFactory.save(srv1);

        Set<ConfigRevision> revisions = new HashSet<>();

        ConfigFile g1f1 = gcc1.createConfigFile(
                ConfigFileState.normal(), "/etc/foo1");
        revisions.add(ConfigTestUtils.createConfigRevision(g1f1));

        ConfigurationFactory.commit(gcc1);

        ConfigFile g1f2 = gcc1.createConfigFile(
                ConfigFileState.normal(), "/etc/foo2");
        revisions.add(ConfigTestUtils.createConfigRevision(g1f2));
        ConfigurationFactory.commit(gcc2);

        ConfigFile g2f2 = gcc2.createConfigFile(
                ConfigFileState.normal(), "/etc/foo4");
        revisions.add(ConfigTestUtils.createConfigRevision(g2f2));
        ConfigurationFactory.commit(gcc2);

        ConfigFile g2f3 = gcc2.createConfigFile(
                ConfigFileState.normal(), "/etc/foo3");
        revisions.add(ConfigTestUtils.createConfigRevision(g2f3));
        ConfigurationFactory.commit(gcc2);

        // System 1 - both g1f1 and g1f2 should deploy here
        Set<Server> systems  = new HashSet<>();
        systems.add(srv1);
        mgr.deployConfiguration(user, systems, new Date());
        DataResult<ScheduledAction> actions = ActionManager.
                                    recentlyScheduledActions(user, null, 1);
        ConfigAction ca = null;
        for (ScheduledAction action : actions) {
            if (ActionFactory.TYPE_CONFIGFILES_DEPLOY.getName().
                    equals(action.getTypeName())) {
                ca = (ConfigAction)ActionManager.lookupAction(user,
                        action.getId());
            }
        }
        assertNotNull(ca);
        assertEquals(revisions.size(), ca.getConfigRevisionActions().size());
        for (ConfigRevisionAction cra : ca.getConfigRevisionActions()) {
            assertTrue(revisions.contains(cra.getConfigRevision()));
        }
    }

    @Test
    public void testDeployFiles() throws Exception {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);

        ConfigurationManager mgr = ConfigurationManager.getInstance();

        // Create  global config channels
        ConfigChannel gcc1 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        ConfigChannel gcc2 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());

        Long ver = 2L;

        // gcc1 only
        Server srv1 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv1.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);

        // gcc2 only
        Server srv2 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv2.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);

        // f1 from gcc2, f2 from gcc2
        Server srv3 = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srv3.getId(),
                SystemManager.CAP_CONFIGFILES_DEPLOY, ver);

        srv1.subscribeConfigChannel(gcc1, user);
        srv2.subscribeConfigChannel(gcc2, user);
        srv3.subscribeConfigChannel(gcc1, user);
        srv3.subscribeConfigChannel(gcc2, user);
        ServerFactory.save(srv1);
        ServerFactory.save(srv2);
        ServerFactory.save(srv3);

        ConfigFile g1f1 = gcc1.createConfigFile(
                ConfigFileState.normal(), "/etc/foo1");
        ConfigTestUtils.createConfigRevision(g1f1);
        ConfigurationFactory.commit(gcc1);

        ConfigFile g1f2 = gcc1.createConfigFile(
                ConfigFileState.normal(), "/etc/foo2");
        ConfigTestUtils.createConfigRevision(g1f2);
        ConfigurationFactory.commit(gcc2);

        ConfigFile g2f2 = gcc2.createConfigFile(
                ConfigFileState.normal(), "/etc/foo2");
        ConfigTestUtils.createConfigRevision(g2f2);
        ConfigurationFactory.commit(gcc2);

        ConfigFile g2f3 = gcc2.createConfigFile(
                ConfigFileState.normal(), "/etc/foo3");
        ConfigTestUtils.createConfigRevision(g2f3);
        ConfigurationFactory.commit(gcc2);

        // System 1 - both g1f1 and g1f2 should deploy here
        Set<Long> systems = new HashSet<>();
        Set<Long> revs = new HashSet<>();
        systems.add(srv1.getId());
        revs.add(g1f1.getId());
        revs.add(g1f2.getId());
        Map<String, Long> m = mgr.deployFiles(user, revs, systems, new Date());
        assertNotNull(m);
        assertEquals(m.get("success"), 2L);
        assertNull(m.get("override"));

        // System 3 - g2f2 should be overridden by g1f2, and g2f3 should deploy
        systems = new HashSet<>();
        revs = new HashSet<>();
        systems.add(srv3.getId());
        revs.add(g2f2.getId());
        revs.add(g2f3.getId());
        m = mgr.deployFiles(user, revs, systems, new Date());
        assertNotNull(m);
        assertEquals(m.get("success"), 1L);
        assertEquals(m.get("override"), 1L);
    }

    @Test
    public void testListManagedFilePaths() {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);

        // Create  global config channels
        ConfigChannel gcc1 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        ConfigChannel gcc2 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        Server srv1 = ServerFactoryTest.createTestServer(user, true);
        srv1.subscribeConfigChannel(gcc1, user);
        srv1.subscribeConfigChannel(gcc2, user);

        //we want the items here to be in sorted order
        // 0, 1 will be used to test Centrally managed paths
        // 1, 2 will be used to test Locally managed paths
        final String[] paths = {"/etc/foo1", "/etc/foo2", "/etc/foo3"};

        ConfigFile g1f1 = gcc1.createConfigFile(
                ConfigFileState.normal(), paths[0]);
        ConfigRevision rev1 = ConfigTestUtils.createConfigRevision(g1f1);
        ConfigurationFactory.commit(gcc1);

        // create a new revision so that the revision number is bumped

        rev1 = ConfigTestUtils.createConfigRevision(g1f1,
                                ConfigTestUtils.createConfigContent(),
                                ConfigTestUtils.createConfigInfo(),
                rev1.getRevision() + 1);
        ConfigurationFactory.commit(gcc1);

        //add a duuplicate file to gcc2
        ConfigFile g1f2 = gcc2.createConfigFile(
                ConfigFileState.normal(), paths[0]);
        ConfigTestUtils.createConfigRevision(g1f2);
        ConfigurationFactory.commit(gcc2);


        ConfigFile g1f3 = gcc2.createConfigFile(
                ConfigFileState.normal(), paths[1]);
        ConfigRevision rev3 = ConfigTestUtils.createConfigRevision(g1f3);
        ConfigurationFactory.commit(gcc2);

        ServerFactory.save(srv1);
        List<ConfigFileNameDto> localViewResults = cm.listManagedPathsFor(srv1,
                                               user,
                                ConfigChannelType.local());

        assertTrue(localViewResults == null || localViewResults.isEmpty());

        List<ConfigFileNameDto> globalViewResults = cm.listManagedPathsFor(srv1,
                                     user,
                                     ConfigChannelType.normal());
        assertEquals(2, globalViewResults.size());

        Iterator<ConfigFileNameDto> itr =  globalViewResults.iterator();
        ConfigFileNameDto dto = itr.next();
        assertEquals(dto.getPath(), paths[0]);
        assertEquals(dto.getConfigRevision(), rev1.getRevision());
        assertNull(dto.getLocalRevision());
        assertNull(dto.getLocalRevisionId());

        dto = itr.next();
        assertEquals(dto.getPath(), paths[1]);
        assertEquals(dto.getConfigRevision(), rev3.getRevision());
        assertNull(dto.getLocalRevision());
        assertNull(dto.getLocalRevisionId());

        //NOW add a local override with a duplicate file path
        // and make sure  it shows up in the output..
        ConfigChannel local = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.local());
        srv1.setLocalOverride(local);
        ConfigFile g1f4 = local.createConfigFile(
                ConfigFileState.normal(), paths[1]);
        ConfigRevision rev4 = ConfigTestUtils.createConfigRevision(g1f4);
        ConfigurationFactory.commit(local);

        ServerFactory.save(srv1);


        globalViewResults = cm.listManagedPathsFor(srv1, user,
                               ConfigChannelType.normal());
        assertEquals(2, globalViewResults.size());

        itr =  globalViewResults.iterator();
        dto = itr.next();
        assertEquals(dto.getPath(), paths[0]);
        assertEquals(dto.getConfigRevision(), rev1.getRevision());
        assertNull(dto.getLocalRevision());
        assertNull(dto.getLocalRevisionId());
        assertEquals(ConfigChannelType.normal().getLabel(),
                dto.getConfigChannelType());

        dto = itr.next();
        assertEquals(dto.getPath(), paths[1]);
        assertEquals(dto.getConfigRevision(), rev3.getRevision());
        assertEquals(dto.getLocalRevision(), rev4.getRevision());
        assertEquals(dto.getLocalRevisionId().longValue(),
                                    rev4.getId().longValue());

        // now lets test the list Managed For Local
        ConfigFile g1f5 = local.createConfigFile(
                ConfigFileState.normal(), paths[2]);
        ConfigRevision rev5 = ConfigTestUtils.createConfigRevision(g1f5);
        ConfigurationFactory.commit(local);

        ServerFactory.save(srv1);



        localViewResults = cm.listManagedPathsFor(srv1,
                                  user,
                                  ConfigChannelType.local());
        assertEquals(2, localViewResults.size());
        dto = localViewResults.get(0);
        assertEquals(dto.getPath(), paths[1]);
        assertEquals(dto.getLocalRevision(),  rev4.getRevision());
        assertEquals(dto.getConfigRevision(), rev3.getRevision());
        assertEquals(ConfigChannelType.local().getLabel(),
                dto.getConfigChannelType());

        dto = localViewResults.get(1);
        assertEquals(dto.getPath(), paths[2]);
        assertEquals(dto.getLocalRevision(),  rev5.getRevision());
        assertEquals(dto.getLocalRevisionId().longValue(),
                                            rev5.getId().longValue());
        assertNull(dto.getConfigRevision());

    }

    @Test
    public void testSandboxManagedFilePaths() {
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);

        // Create  Sandbox  config channel
        ConfigChannel sandbox = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.sandbox());
        Server srv1 = ServerFactoryTest.createTestServer(user, true);
        srv1.setSandboxOverride(sandbox);


        //we want the items here to be in sorted order
        // 0, 1 will be used to test Centrally managed paths
        // 1, 2 will be used to test Locally managed paths
        final String[] paths = {"/etc/foo1", "/etc/foo2", "/etc/foo3"};


        List<Long> revisions = new ArrayList<>();

        for (String pathIn : paths) {
            ConfigFile fl = sandbox.createConfigFile(
                    ConfigFileState.normal(), pathIn);
            ConfigRevision rev = ConfigTestUtils.createConfigRevision(fl,
                    ConfigTestUtils.createConfigContent(),
                    ConfigTestUtils.createConfigInfo(),
                    (long) RandomUtils.nextInt(0,
                            Integer.MAX_VALUE)
            );
            revisions.add(rev.getRevision());
            ConfigurationFactory.commit(sandbox);
        }
        ServerFactory.save(srv1);
        List<ConfigFileNameDto> sandboxViewResults = cm.listManagedPathsFor(srv1, user, ConfigChannelType.sandbox());

        assertEquals(paths.length, sandboxViewResults.size());
        for (int i = 0; i < paths.length; i++) {
            ConfigFileNameDto dto = sandboxViewResults.get(i);
            assertEquals(revisions.get(i), dto.getConfigRevision());
            assertEquals(ConfigChannelType.sandbox().getLabel(),
                                                    dto.getConfigChannelType());
            assertEquals(dto.getPath(), paths[i]);
            assertNotNull(dto.getLastModifiedDate());
        }
    }

    @Test
    public void testCopyFile() throws Exception {
        // Create  global config channels
        ConfigChannel gcc1 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());

        /**
         * Giving the user access to this channel
         * but note he is NOT a config admin
         */
        ConfigTestUtils.giveUserChanAccess(user, gcc1);

        ConfigFile g1f1 = gcc1.createConfigFile(
                ConfigFileState.normal(), "/etc/foo1");
        ConfigRevision cr = ConfigTestUtils.createConfigRevision(g1f1);
        ConfigurationFactory.commit(gcc1);

        ConfigChannel gcc2 = ConfigTestUtils.createConfigChannel(user.getOrg(),
                                  ConfigChannelType.normal());

        try {
            /**
             * this operation should fail because the user
             * is not a config admin and hence cannot copy stuff
             * to gcc2.
             */
            cm.copyConfigFile(cr, gcc2, user);
            fail("Invalid Access not detected!.");
        }
        catch (Exception ie) {
            assertEquals(IllegalArgumentException.class, ie.getClass());
        }

        try {
            /**
             * this operation should fail because the user
             * is not a config admin and hence cannot copy stuff
             * to gcc2.
             */
            cm.copyConfigFile(cr, gcc2, user);
            fail("Invalid Access not detected!.");
        }
        catch (Exception ie) {
            assertEquals(IllegalArgumentException.class, ie.getClass());
        }

        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);
        UserFactory.save(user);
        OrgFactory.save(user.getOrg());

        try {
            /**
             * this operation should Succeed because the user
             * is A config admin and hence can copy stuff to any global channel
             * including gcc2.
             */
            cm.copyConfigFile(cr, gcc2, user);
            gcc2 = TestUtils.reload(gcc2);
            assertNotNull(gcc2);
            assertNotNull(gcc2.getConfigFiles());
            assertEquals(1, gcc2.getConfigFiles().size());
            ConfigFile fl = gcc2.getConfigFiles().first();
            assertEquals(g1f1.getConfigFileName(), fl.getConfigFileName());
            assertEquals(g1f1.getLatestConfigRevision().getConfigFileType(),
                               fl.getLatestConfigRevision().getConfigFileType());
        }
        catch (IllegalArgumentException ie) {
            throw new Exception("Valid Access not detected!.", ie);
        }
    }
    @Test
    public void testChannelAccess() {
        // Create a server we DON'T own - we shouldn't have channel access
        Server srv = ServerFactoryTest.createTestServer(user, false);

        ConfigChannel cc = srv.getLocalOverride();
        assertNotNull(cc);
        assertFalse(cm.accessToChannel(user.getId(), cc.getId()));

        cc = srv.getSandboxOverride();
        assertNotNull(cc);
        assertFalse(cm.accessToChannel(user.getId(), cc.getId()));

        // Create a server we DO own - we SHOULD have channel access
        srv = ServerFactoryTest.createTestServer(user, true);

        cc = srv.getLocalOverride();
        assertNotNull(cc);
        assertTrue(cm.accessToChannel(user.getId(), cc.getId()));

        cc = srv.getSandboxOverride();
        assertNotNull(cc);
        assertTrue(cm.accessToChannel(user.getId(), cc.getId()));

        // Create a global config-channel - we should NOT have access
        cc = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        assertNotNull(cc);
        assertFalse(cm.accessToChannel(user.getId(), cc.getId()));

        // Subscribe "our" system to that channel - we SHOULD have access
        srv.subscribeConfigChannel(cc, user);
        ServerFactory.save(srv);
        assertTrue(cm.accessToChannel(user.getId(), cc.getId()));

        // Create a second global channel - we should NOT have access
        cc = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());
        assertNotNull(cc);
        assertFalse(cm.accessToChannel(user.getId(), cc.getId()));

        // Make us config-admin - we SHOULD have access
        UserTestUtils.addAccessGroup(user, AccessGroupFactory.CONFIG_ADMIN);
        assertTrue(cm.accessToChannel(user.getId(), cc.getId()));
    }

    /**
     * Tests listing of non-config-managed systems that are capable for config management.
     *
     * @throws Exception if anything goes wrong
     */
    @Test
    public void testListCapableSystems() throws Exception {
        Server minion = MinionServerFactoryTest.createTestMinionServer(user);
        Server tradClient = ServerFactoryTest.createUnentitledTestServer(user, true,
                ServerFactoryTest.TYPE_SERVER_NORMAL, new Date());

        List<ConfigSystemDto> systems = ConfigurationManager.getInstance()
                .listNonManagedSystems(user, null);

        assertEquals(1, systems.stream()
                .filter(s -> s.getId().equals(tradClient.getId()))
                .count());
        assertEquals(0, systems.stream()
                .filter(s -> s.getId().equals(minion.getId()))
                .count());
    }

    /**
     * Tests listing of non-config-managed systems that are capable for config management.
     *
     * @throws Exception if anything goes wrong
     */
    @Test
    public void testListCapableSystemsInSet() throws Exception {
        Server minion = MinionServerFactoryTest.createTestMinionServer(user);
        Server tradClient = ServerFactoryTest.createUnentitledTestServer(user, true,
                ServerFactoryTest.TYPE_SERVER_NORMAL, new Date());

        ServerTestUtils.addServersToSsm(user, tradClient.getId(), minion.getId());

        String setLabel = RhnSetDecl.SYSTEMS.getLabel();
        List<ConfigSystemDto> systems = ConfigurationManager.getInstance()
                .listNonManagedSystemsInSet(user, null, setLabel);

        assertEquals(1, systems.stream()
                .filter(s -> s.getId().equals(tradClient.getId()))
                .count());
        assertEquals(0, systems.stream()
                .filter(s -> s.getId().equals(minion.getId()))
                .count());
    }

    /**
     * Test method for determining if a channel is duplicated.
     */
    @Test
    public void testIsNormalChannelDuplicated() {
        ConfigChannel channel = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.normal());

        assertTrue(ConfigurationManager.conflictingChannelExists(channel.getLabel(),
                ConfigChannelType.normal(),
                channel.getOrg()));

        assertTrue(ConfigurationManager.conflictingChannelExists(channel.getLabel(),
                ConfigChannelType.state(),
                channel.getOrg()));

        assertFalse(ConfigurationManager.conflictingChannelExists(channel.getLabel(),
                ConfigChannelType.local(),
                channel.getOrg()));
    }

    /**
     * Test method for determining if a channel is duplicated.
     */
    @Test
    public void testIsLocalChannelDuplicated() {
        ConfigChannel channel = ConfigTestUtils.createConfigChannel(user.getOrg(),
                ConfigChannelType.local());

        assertFalse(ConfigurationManager.conflictingChannelExists(channel.getLabel(),
                ConfigChannelType.normal(),
                channel.getOrg()));

        assertFalse(ConfigurationManager.conflictingChannelExists(channel.getLabel(),
                ConfigChannelType.state(),
                channel.getOrg()));

        assertTrue(ConfigurationManager.conflictingChannelExists(channel.getLabel(),
                ConfigChannelType.local(),
                channel.getOrg()));
    }
}

