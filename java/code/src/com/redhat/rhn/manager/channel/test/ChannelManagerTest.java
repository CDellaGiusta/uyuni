/*
 * Copyright (c) 2009--2015 Red Hat, Inc.
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
package com.redhat.rhn.manager.channel.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.redhat.rhn.common.conf.ConfigDefaults;
import com.redhat.rhn.common.db.datasource.DataResult;
import com.redhat.rhn.common.hibernate.HibernateFactory;
import com.redhat.rhn.common.validator.ValidatorException;
import com.redhat.rhn.domain.access.AccessGroupFactory;
import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.channel.AccessTokenFactory;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.ChannelFactory;
import com.redhat.rhn.domain.channel.ChannelVersion;
import com.redhat.rhn.domain.channel.DistChannelMap;
import com.redhat.rhn.domain.channel.ProductName;
import com.redhat.rhn.domain.channel.ReleaseChannelMap;
import com.redhat.rhn.domain.channel.test.ChannelFactoryTest;
import com.redhat.rhn.domain.errata.AdvisoryStatus;
import com.redhat.rhn.domain.errata.Errata;
import com.redhat.rhn.domain.errata.ErrataFactory;
import com.redhat.rhn.domain.errata.test.ErrataFactoryTest;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.org.OrgFactory;
import com.redhat.rhn.domain.product.SUSEProduct;
import com.redhat.rhn.domain.product.SUSEProductFactory;
import com.redhat.rhn.domain.product.test.SUSEProductTestUtils;
import com.redhat.rhn.domain.rhnpackage.Package;
import com.redhat.rhn.domain.rhnpackage.test.PackageTest;
import com.redhat.rhn.domain.rhnset.RhnSet;
import com.redhat.rhn.domain.role.RoleFactory;
import com.redhat.rhn.domain.server.MinionServer;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.server.ServerFactory;
import com.redhat.rhn.domain.server.test.MinionServerFactoryTest;
import com.redhat.rhn.domain.server.test.ServerFactoryTest;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.domain.user.UserFactory;
import com.redhat.rhn.frontend.action.channel.manage.ErrataHelper;
import com.redhat.rhn.frontend.dto.ChannelOverview;
import com.redhat.rhn.frontend.dto.ChannelTreeNode;
import com.redhat.rhn.frontend.dto.ChildChannelDto;
import com.redhat.rhn.frontend.dto.ErrataOverview;
import com.redhat.rhn.frontend.dto.EssentialChannelDto;
import com.redhat.rhn.frontend.dto.PackageDto;
import com.redhat.rhn.frontend.dto.PackageOverview;
import com.redhat.rhn.frontend.dto.SystemsPerChannelDto;
import com.redhat.rhn.frontend.xmlrpc.NoSuchChannelException;
import com.redhat.rhn.manager.action.ActionManager;
import com.redhat.rhn.manager.channel.ChannelManager;
import com.redhat.rhn.manager.channel.EusReleaseComparator;
import com.redhat.rhn.manager.channel.MultipleChannelsWithPackageException;
import com.redhat.rhn.manager.errata.ErrataManager;
import com.redhat.rhn.manager.rhnpackage.test.PackageManagerTest;
import com.redhat.rhn.manager.rhnset.RhnSetDecl;
import com.redhat.rhn.manager.rhnset.RhnSetManager;
import com.redhat.rhn.manager.ssm.SsmManager;
import com.redhat.rhn.manager.system.SystemManager;
import com.redhat.rhn.taskomatic.TaskomaticApi;
import com.redhat.rhn.taskomatic.TaskomaticApiException;
import com.redhat.rhn.testing.BaseTestCaseWithUser;
import com.redhat.rhn.testing.ChannelTestUtils;
import com.redhat.rhn.testing.ServerTestUtils;
import com.redhat.rhn.testing.TestUtils;
import com.redhat.rhn.testing.UserTestUtils;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.imposters.ByteBuddyClassImposteriser;
import org.jmock.junit5.JUnit5Mockery;
import org.jmock.lib.concurrent.Synchroniser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * ChannelManagerTest
 */
@SuppressWarnings("deprecation")
@ExtendWith(JUnit5Mockery.class)
public class ChannelManagerTest extends BaseTestCaseWithUser {

    private static final String TEST_OS = "TEST RHEL AS";
    private static final String MAP_RELEASE = "4AS";

    @RegisterExtension
    protected final Mockery mockContext = new JUnit5Mockery() {{
        setThreadingPolicy(new Synchroniser());
        setImposteriser(ByteBuddyClassImposteriser.INSTANCE);
    }};

    private static TaskomaticApi taskomaticApi;

    @Test
    public void testAllDownloadsTree() {
    }

    @Test
    public void testListDownloadCategories() {
    }

    @Test
    public void testListDownloadImages() {
    }

    @Test
    public void testAddRemoveSubscribeRole() throws Exception {
        User admin = UserTestUtils.createUser("adminUser", user.getOrg().getId());
        Channel channel = ChannelFactoryTest.createTestChannel(admin);
        channel.setGloballySubscribable(false, admin.getOrg());
        assertFalse(channel.isGloballySubscribable(admin.getOrg()));

        assertFalse(ChannelManager.verifyChannelSubscribe(user, channel.getId()));

        ChannelManager.addSubscribeRole(user, channel);
        assertTrue(ChannelManager.verifyChannelSubscribe(user, channel.getId()));

        ChannelManager.removeSubscribeRole(user, channel);
        assertFalse(ChannelManager.verifyChannelSubscribe(user, channel.getId()));
    }

    @Test
    public void testChannelsInOrg() throws Exception {
        // get an org
        Org org = OrgFactory.lookupById(UserTestUtils.createOrg("channelTestOrg"));
        //put a channel in the org
        Channel channel = ChannelFactoryTest.createTestChannel(org);
        org.addOwnedChannel(channel);
        //save the org
        OrgFactory.save(org);
        //inspect the data result
        DataResult<ChannelOverview> dr =
                ChannelManager.channelsOwnedByOrg(org.getId(), null);
        assertNotNull(dr); //should be at least one item in there
    }

    @Test
    public void testChannelsForUser() throws Exception {
        ChannelFactoryTest.createTestChannel(user);
        List<String> channels = ChannelManager.channelsForUser(user);

        //make sure we got a list out
        assertNotNull(channels);

    }

    @Test
    public void testVendorChannelTree() throws Exception {

        Channel channel = ChannelFactoryTest.createTestChannel(user);
        channel.setOrg(null);

        OrgFactory.save(user.getOrg());
        ChannelFactory.save(channel);
        DataResult<ChannelTreeNode> dr = ChannelManager.vendorChannelTree(user, null);
        assertNotEmpty(dr);
    }

    @Test
   public void testMyChannelTree() throws Exception {

        Channel channel = ChannelFactoryTest.createTestChannel(user);
        user.getOrg().addOwnedChannel(channel);

        OrgFactory.save(user.getOrg());
        ChannelFactory.save(channel);
        DataResult<ChannelTreeNode> dr = ChannelManager.myChannelTree(user, null);
        assertNotEmpty(dr);
    }


    @Test
   public void testPopularChannelTree() throws Exception {
       Server server = ServerFactoryTest.createTestServer(user, true);
       ServerFactory.save(server);
       Channel channel = ChannelFactoryTest.createTestChannel(user);
       ChannelFactory.save(channel);
       user.getOrg().addOwnedChannel(channel);
       OrgFactory.save(user.getOrg());

        DataResult<ChannelTreeNode> dr = ChannelManager.popularChannelTree(user, 1L, null);

       assertTrue(dr.isEmpty());
       SystemManager.unsubscribeServerFromChannel(user, server, server.getBaseChannel());
       SystemManager.subscribeServerToChannel(user, server, channel);

       dr = ChannelManager.popularChannelTree(user, 1L, null);

       assertFalse(dr.isEmpty());
   }


    @Test
    public void testAllChannelTree() throws Exception {

        Channel channel = ChannelFactoryTest.createTestChannel(user);
        channel.setEndOfLife(new Date(System.currentTimeMillis() + Integer.MAX_VALUE));
        user.getOrg().addOwnedChannel(channel);

        OrgFactory.save(user.getOrg());
        ChannelFactory.save(channel);
        DataResult<ChannelTreeNode> dr = ChannelManager.allChannelTree(user, null);
        assertNotEmpty(dr);
    }

    @Test
    public void testOrphanedChannelTree() throws Exception {
        Channel channel = ChannelFactoryTest.createTestChannel(user);
        channel.setEndOfLife(new Date(System.currentTimeMillis() + 10000000L));
        user.getOrg().addOwnedChannel(channel);

        Channel childChannel = ChannelFactoryTest.createTestChannel(user);
        childChannel.setParentChannel(channel);

        OrgFactory.save(user.getOrg());
        ChannelFactory.save(channel);
        ChannelFactory.save(childChannel);
        flushAndEvict(channel);
        flushAndEvict(childChannel);

        DataResult<ChannelTreeNode> dr = ChannelManager.allChannelTree(user, null);
        assertNotEmpty(dr);
    }

    @Test
    public void testOwnedChannelsTree() {
        assertTrue(ChannelManager.ownedChannelsTree(UserTestUtils.findNewUser()).isEmpty());
        assertNotEmpty(ChannelManager.ownedChannelsTree(user));
    }

    @Test
    public void testRetiredChannelTree() throws Exception {
        Channel channel = ChannelFactoryTest.createTestChannel(user);
        channel.setEndOfLife(new Date(System.currentTimeMillis() - 1000000));
        user.getOrg().addOwnedChannel(channel);
        channel.setGloballySubscribable(true, user.getOrg());

        OrgFactory.save(user.getOrg());
        ChannelFactory.save(channel);

        DataResult<ChannelTreeNode> dr = ChannelManager.retiredChannelTree(user, null);
        assertNotEmpty(dr);
    }

    @Test
    public void testAccessibleChannels() throws Exception {
        Channel parent = ChannelFactoryTest.createBaseChannel(user);
        Channel child = ChannelFactoryTest.createTestChannel(user);
        child.setParentChannel(parent);
        TestUtils.saveAndFlush(child);
        TestUtils.saveAndFlush(parent);

        List<Channel> dr =
                ChannelManager.userAccessibleChildChannels(user.getOrg().getId(),
                parent.getId());

        assertFalse(dr.isEmpty());
    }

    @Test
    public void testChannelArches() {
        // for a more detailed test see ChannelFactoryTest
        assertNotNull(ChannelManager.getChannelArchitectures());
    }

    @Test
    public void testUpdateSystemsChannelsInfo() throws Exception {
        ActionManager.setTaskomaticApi(getTaskomaticApi());

        MinionServer testMinionServer = MinionServerFactoryTest.createTestMinionServer(user);
        Channel base = ChannelFactoryTest.createBaseChannel(user);
        Channel child = ChannelFactoryTest.createTestChannel(user);
        testMinionServer.addChannel(base);
        testMinionServer.addChannel(child);
        assertTrue(AccessTokenFactory.generate(testMinionServer, Collections.singleton(base)).isPresent());
        assertTrue(AccessTokenFactory.generate(testMinionServer, Collections.singleton(child)).isPresent());
        MinionServer minionServer = TestUtils.saveAndReload(testMinionServer);

        ChannelManager.deleteChannel(user, child.getLabel(), true);
        Optional<Long> actionId = ChannelManager.applyChannelState(user, Collections.singletonList(minionServer));
        assertEquals(1, minionServer.getChannels().size());
        assertTrue(actionId.isPresent());
    }

    @Test
    public void testDeleteChannel() throws Exception {
        // thanks mmccune for the tip
        user.getOrg().addRole(RoleFactory.CHANNEL_ADMIN);
        user.addToGroup(AccessGroupFactory.CHANNEL_ADMIN);
        TestUtils.saveAndFlush(user);

        Channel c = ChannelFactoryTest.createTestChannel(user);
        c = (Channel) reload(c);
        ChannelManager.deleteChannel(user, c.getLabel(), true);
        assertNull(reload(c));
    }

    @Test
    public void testDeleteClonedChannel() throws Exception {
        user.getOrg().addRole(RoleFactory.CHANNEL_ADMIN);
        user.addToGroup(AccessGroupFactory.CHANNEL_ADMIN);
        TestUtils.saveAndFlush(user);

        Channel c = ChannelFactoryTest.createTestChannel(user);
        Channel cClone1 = ChannelFactoryTest.createTestClonedChannel(c, user);
        Channel cClone2 = ChannelFactoryTest.createTestClonedChannel(cClone1, user);
        cClone2 = (Channel) reload(cClone2);
        ChannelManager.deleteChannel(user, cClone2.getLabel(), true);
        assertNotNull(reload(c));
        assertNotNull(reload(cClone1));
        assertNull(reload(cClone2));
    }

    @Test
    public void testDeleteChannelWithClones() throws Exception {
        user.getOrg().addRole(RoleFactory.CHANNEL_ADMIN);
        user.addToGroup(AccessGroupFactory.CHANNEL_ADMIN);
        TestUtils.saveAndFlush(user);

        Channel c = ChannelFactoryTest.createTestChannel(user);
        Channel cClone1 = ChannelFactoryTest.createTestClonedChannel(c, user);
        Channel cClone2 = ChannelFactoryTest.createTestClonedChannel(cClone1, user);
        cClone1 = (Channel) reload(cClone1);
        try {
            ChannelManager.deleteChannel(user, cClone1.getLabel(), true);
            fail();
        }
        catch (ValidatorException exc) {
            assertEquals(exc.getResult().getErrors().size(), 1);
            assertEquals(exc.getResult().getErrors().get(0).getKey(), "api.channel.delete.hasclones");
            assertNotNull(reload(c));
            assertNotNull(reload(cClone1));
            assertNotNull(reload(cClone2));
        }
    }

    @Test
    public void testDeleteChannelException() throws Exception {
        try {
            ChannelManager.deleteChannel(user, "jesusr-channel-test");
        }
        catch (NoSuchChannelException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testLatestPackages() {
    }

    @Test
    public void testListErrata() throws Exception {
        Channel c = ChannelFactoryTest.createTestChannel(user);
        Errata e = ErrataFactoryTest.createTestErrata(user.getOrg().getId());
        List<Errata> errataList = new ArrayList<>();
        errataList.add(e);
        ErrataFactory.addToChannel(errataList, c, user, false);

        e = (Errata) TestUtils.saveAndReload(e);

        List<ErrataOverview> errata = ChannelManager.listErrata(c, null, null, false, user);
        boolean found = false;
        for (ErrataOverview eo : errata) {
            if (eo.getId().equals(e.getId())) {
                found = true;
            }
        }
        assertTrue(found);


        found = false;
        Date date = new Date();
        errata = ChannelManager.listErrata(c, new Date(date.getTime() - 100000),
                null, false, user);
        for (ErrataOverview eo : errata) {
            if (eo.getId().equals(e.getId())) {
                found = true;
            }
        }
        assertTrue(found);

        found = false;
        errata = ChannelManager.listErrata(c, new Date(date.getTime() - 100000),
                                    new Date(date.getTime() + 5000000), false, user);
        for (ErrataOverview eo : errata) {
            if (eo.getId().equals(e.getId())) {
                found = true;
            }
        }
        assertTrue(found);
    }

    @Test
    public void testPackagesLike() throws Exception {
        Server s = ServerFactoryTest.createTestServer(user);
        Channel c = ChannelFactoryTest.createTestChannel(user);
        PackageManagerTest.addPackageToSystemAndChannel("some-test-package", s, c);
        assertEquals(1, ChannelManager.listLatestPackagesEqual(c.getId(),
                "some-test-package").size());
        assertEquals(1, ChannelManager.listLatestPackagesLike(c.getId(),
                "some-test-").size());
        assertNotNull(ChannelManager.getLatestPackageEqual(c.getId(),
                "some-test-package"));
    }

    @Test
    public void testBaseChannelsForSystem() throws Exception {
        Server s = ServerTestUtils.createTestSystem(user);

        ChannelTestUtils.createTestChannel(user);
        ChannelTestUtils.createTestChannel(user);
        List<EssentialChannelDto> channels = ChannelManager.listBaseChannelsForSystem(user, s);

        assertTrue(channels.size() >= 2);
    }

    @Test
    public void testBaseChannelsForSystemSorted() throws Exception {
        Server s = ServerTestUtils.createTestSystem(user);

        Channel c = ChannelTestUtils.createTestChannel(user);
        c.setName("A Channel");
        TestUtils.saveAndReload(c);
        c = ChannelTestUtils.createTestChannel(user);
        c.setName("C Channel");
        TestUtils.saveAndReload(c);
        c = ChannelTestUtils.createTestChannel(user);
        c.setName("B Channel");
        TestUtils.saveAndReload(c);

        List<String> channelNames = ChannelManager.listBaseChannelsForSystem(user, s).stream()
                .map(EssentialChannelDto::getName).toList();

        assertTrue(channelNames.indexOf("A Channel") < channelNames.indexOf("B Channel"));
        assertTrue(channelNames.indexOf("B Channel") < channelNames.indexOf("C Channel"));
    }

    @Test
    public void testBaseChannelsForLiberty() throws Exception {
        Server s = MinionServerFactoryTest.createTestMinionServer(user);

        // load official product data as test data into the DB
        s.setServerArch(ServerFactory.lookupServerArchByLabel("x86_64-redhat-linux"));
        SUSEProductTestUtils.createVendorSUSEProductEnvironment(user,
                "/com/redhat/rhn/manager/content/test/data4", true);
        HibernateFactory.getSession().flush();
        HibernateFactory.getSession().clear();

        // "mirror" the products and mandatory base channels
        SUSEProduct resProduct = SUSEProductFactory.findSUSEProduct("res", "7", "", "x86_64", true);
        assertNotNull(resProduct);
        SUSEProduct resLtssProduct = SUSEProductFactory.findSUSEProduct("res-ltss", "7", "", "x86_64", true);
        assertNotNull(resLtssProduct);
        SUSEProductTestUtils.createBaseChannelForBaseProduct(resProduct, user);
        SUSEProductTestUtils.createBaseChannelForBaseProduct(resLtssProduct, user);

        // Test: list base channels for Liberty 7
        SUSEProductTestUtils.installSUSEProductOnServer(resProduct, s);

        List<EssentialChannelDto> channels = ChannelManager.listBaseChannelsForSystem(user, s);

        assertEquals(3, channels.size());
        List<String> expectedNames = new ArrayList<>(List.of(
                "Channel for SUSE Liberty Linux 7 x86_64",
                "Channel for SUSE Liberty Linux LTSS 7 x86_64"));
        List<String> names = channels.stream()
                .filter(c -> !c.isCustom())
                .map(EssentialChannelDto::getName).toList();
        expectedNames.removeAll(names);
        assertTrue(expectedNames.isEmpty(), "Missing expected channel names: " + expectedNames);
    }

    public static ReleaseChannelMap createReleaseChannelMap(Channel channel, String product,
            String version, String release) {

        ReleaseChannelMap rcm = new ReleaseChannelMap();
        rcm.setChannel(channel);
        rcm.setChannelArch(channel.getChannelArch());
        rcm.setProduct(product);
        rcm.setVersion(version);
        rcm.setRelease(release);
        TestUtils.saveAndReload(rcm);
        return rcm;
    }

    @Test
    public void testLookupDefaultReleaseChannelMap() throws Exception {
        Channel base1 = ChannelFactoryTest.createBaseChannel(user);
        String version = "5Server";
        String release = "5.0.0";
        ChannelManagerTest.createReleaseChannelMap(base1, "MAP_OS", version,
                release);

        ReleaseChannelMap rcm = ChannelManager.lookupDefaultReleaseChannelMapForChannel(
                base1);
        assertEquals(version, rcm.getVersion());
        assertEquals(release, rcm.getRelease());
    }

    @Test
    public void testBaseChannelsForSystemIncludesEus() throws Exception {
        Server s = ServerTestUtils.createTestSystem(user);
        String version = "5Server";
        String release = "5.0.0.9";
        s = ServerTestUtils.addRedhatReleasePackageToServer(user, s, version, release);
        String release2 = "5.2.0.4";
        String release3 = "5.3.0.3";
        // Create some base channels and corresponding entries in rhnReleaseChannelMap:
        Channel base1 = ChannelFactoryTest.createBaseChannel(user);
        Channel base2 = ChannelFactoryTest.createBaseChannel(user);
        // not sure why we create this third one, but I'll leave it here.
        // jesusr 2007/11/15
        // making sure it's not included in the final results
        // -- dgoodwin
        ChannelFactoryTest.createBaseChannel(user);

        ChannelManagerTest.createReleaseChannelMap(base1,
                ChannelManager.RHEL_PRODUCT_NAME, version, release2);
        ChannelManagerTest.createReleaseChannelMap(base2,
                ChannelManager.RHEL_PRODUCT_NAME, version, release3);
        HibernateFactory.getSession().flush();

        List<EssentialChannelDto> channels = ChannelManager.listBaseChannelsForSystem(user, s);
        assertTrue(channels.size() >= 2);
    }

    @Test
    public void testListBaseEusChannelsByVersionReleaseAndChannelArch() throws Exception {
        String version = "5Server";

        // Create some base channels and corresponding entries in rhnReleaseChannelMap:
        Channel rhel50 = ChannelFactoryTest.createBaseChannel(user);
        Channel rhel51 = ChannelFactoryTest.createBaseChannel(user);
        Channel rhel52 = ChannelFactoryTest.createBaseChannel(user);
        Channel rhel53 = ChannelFactoryTest.createBaseChannel(user);
        Channel rhel6 = ChannelFactoryTest.createBaseChannel(user);
        Channel rhel4 = ChannelFactoryTest.createBaseChannel(user);
        ChannelFactoryTest.createBaseChannel(user);

        ChannelManagerTest.createReleaseChannelMap(rhel50,
                ChannelManager.RHEL_PRODUCT_NAME, version, "5.0.0.0");
        ReleaseChannelMap rcm51 = ChannelManagerTest.createReleaseChannelMap(rhel51,
                ChannelManager.RHEL_PRODUCT_NAME, version, "5.1.0.1");
        ChannelManagerTest.createReleaseChannelMap(rhel52,
                ChannelManager.RHEL_PRODUCT_NAME, version, "5.2.0.2");
        ChannelManagerTest.createReleaseChannelMap(rhel53,
                ChannelManager.RHEL_PRODUCT_NAME, version, "5.3.0.3");
        ChannelManagerTest.createReleaseChannelMap(rhel6,
                ChannelManager.RHEL_PRODUCT_NAME, "6Server", "6.0.0.0");
        ChannelManagerTest.createReleaseChannelMap(rhel4,
                ChannelManager.RHEL_PRODUCT_NAME, "4AS", "4.6.0");

        // For a system with 5.0 already, they should only see RHEL 5 EUS channels
        // with a higher or equal release.
        List<EssentialChannelDto> channels = ChannelManager.
            listBaseEusChannelsByVersionReleaseAndChannelArch(user, rcm51);
        assertTrue(channels.size() >= 2);

        Set<Long> returnedIds = new HashSet<>();
        for (EssentialChannelDto c : channels) {
            returnedIds.add(c.getId());
        }

        assertFalse(returnedIds.contains(rhel50.getId()));
        assertFalse(returnedIds.contains(rhel51.getId()));
        assertTrue(returnedIds.contains(rhel52.getId()));
        assertTrue(returnedIds.contains(rhel53.getId()));
        assertFalse(returnedIds.contains(rhel6.getId()));
        assertFalse(returnedIds.contains(rhel4.getId()));
    }

    @Test
    public void testLookupLatestEusChannelForRhel5() throws Exception {
        String el5version = "5Server";
        String release500 = "5.0.0";
        String release520 = "5.2.0.2";
        String release530 = "5.3.0.3";

        // Create some base channels and corresponding entries in rhnReleaseChannelMap:
        Channel rhel500Chan = ChannelFactoryTest.createBaseChannel(user);
        Channel rhel530Chan = ChannelFactoryTest.createBaseChannel(user);
        Channel rhel520Chan = ChannelFactoryTest.createBaseChannel(user);

        // Creating these in a random order to make sure most recent isn't also
        // most recently created and accidentally getting returned.
        ChannelManagerTest.createReleaseChannelMap(rhel500Chan,
                ChannelManager.RHEL_PRODUCT_NAME, el5version, release500);
        ChannelManagerTest.createReleaseChannelMap(rhel530Chan,
                ChannelManager.RHEL_PRODUCT_NAME, el5version, release530);
        ChannelManagerTest.createReleaseChannelMap(rhel520Chan,
                ChannelManager.RHEL_PRODUCT_NAME, el5version, release520);

        EssentialChannelDto channel = ChannelManager.
            lookupLatestEusChannelForRhelVersion(user, el5version,
                    rhel500Chan.getChannelArch().getId());
        assertEquals(rhel530Chan.getId().longValue(), channel.getId().longValue());
    }

    // Test the problem with string version comparisons is being handled:
    @Test
    public void testLookupLatestEusChannelForRhel5WeirdVersionCompare() throws Exception {
        String el5version = "5Server";
        String release5310 = "5.3.10.0"; // should appear as most recent
        String release539 = "5.3.9.0";

        // Create some base channels and corresponding entries in rhnReleaseChannelMap:
        Channel rhel5310Chan = ChannelFactoryTest.createBaseChannel(user);
        Channel rhel539Chan = ChannelFactoryTest.createBaseChannel(user);

        // Creating these in a random order to make sure most recent isn't also
        // most recently created and accidentally getting returned.
        ChannelManagerTest.createReleaseChannelMap(rhel5310Chan,
                ChannelManager.RHEL_PRODUCT_NAME, el5version, release5310);
        ChannelManagerTest.createReleaseChannelMap(rhel539Chan,
                ChannelManager.RHEL_PRODUCT_NAME, el5version, release539);

        EssentialChannelDto channel = ChannelManager.
            lookupLatestEusChannelForRhelVersion(user, el5version,
                    rhel5310Chan.getChannelArch().getId());
        assertEquals(rhel5310Chan.getId().longValue(), channel.getId().longValue());
    }

    @Test
    public void testLookupLatestEusChannelForRhelVersionNoneFound() throws Exception {
        // Create some base channels and corresponding entries in rhnReleaseChannelMap:
        Channel base1 = ChannelFactoryTest.createBaseChannel(user);
        Channel base2 = ChannelFactoryTest.createBaseChannel(user);
        // Fake some EUS channels for RHEL 6, which should not appear in results:
        ChannelManagerTest.createReleaseChannelMap(base1, TEST_OS, "6Server",
                "6.0.0.0");
        ChannelManagerTest.createReleaseChannelMap(base2, TEST_OS, "6Server",
                "6.1.0.1");

        // Should find nothing:
        EssentialChannelDto channel = ChannelManager.
            lookupLatestEusChannelForRhelVersion(user, "5Server",
                    base1.getChannelArch().getId());
        assertNull(channel);
    }

    @Test
    public void testEusReleaseCmpRhel5() {
        EusReleaseComparator comparator = new EusReleaseComparator("5Server");
        assertEquals(0, comparator.compare("5.3.0.1", "5.3.0.5"));
        assertEquals(0, comparator.compare("5.3.0.1", "5.3.0.10"));
        assertEquals(0, comparator.compare("5.3.0", "5.3.0"));
        assertEquals(1, comparator.compare("5.3.1.1", "5.3.0.10"));
        assertEquals(1, comparator.compare("5.4.1", "5.3.0.10"));
        assertEquals(-1, comparator.compare("5.0.0.0", "5.3.0.3"));
        assertEquals(-1, comparator.compare("5.0.9.0", "5.0.10.0"));
        assertEquals(-1, comparator.compare("5.0.9.0", "5.0.10.0"));
    }

    @Test
    public void testGetToolsChannel() throws Exception {
        Channel base = ChannelTestUtils.createTestChannel(user);
        Channel tools = ChannelTestUtils.createChildChannel(user, base);
        PackageManagerTest.addKickstartPackageToChannel(
                ConfigDefaults.get().getKickstartPackageNames().get(0), tools);

        Channel lookup = ChannelManager.getToolsChannel(base, user);
        assertEquals(tools.getId(), lookup.getId());
    }

    @Test
    public void testGetToolsChannelNoneFound() throws Exception {
        Channel base = ChannelTestUtils.createTestChannel(user);

        Channel lookup = ChannelManager.getToolsChannel(base, user);
        assertNull(lookup);
    }

    @Test
    public void testChildrenAvailableToSet() {
        user.addPermanentRole(RoleFactory.ORG_ADMIN);
        TestUtils.saveAndFlush(user);

        DataResult<ChildChannelDto> childChannels =
                ChannelManager.childrenAvailableToSet(user);
        assertNotNull(childChannels);
        assertTrue(childChannels.isEmpty());
    }

    @Test
    public void testGetChannelVersion() throws Exception {
        Channel c = ChannelTestUtils.createTestChannel(user);
        ChannelTestUtils.addDistMapToChannel(c);
        Set<ChannelVersion> versions = ChannelManager.getChannelVersions(c);
        assertEquals(1, versions.size());
        assertEquals(ChannelVersion.LEGACY, versions.iterator().next());
    }

    @Test
    public void testSubscribeToChildChannelWithPackageName() throws Exception {
        UserTestUtils.addVirtualization(user.getOrg());
        Server s = ServerTestUtils.createTestSystem(user);
        Channel[] chans = ChannelTestUtils.
            setupBaseChannelForVirtualization(s.getCreator(), s.getBaseChannel());

        s.addChannel(chans[0]);
        s.addChannel(chans[1]);
        TestUtils.saveAndReload(s);

        assertNotNull(ChannelManager.subscribeToChildChannelWithPackageName(user,
                s, ChannelManager.TOOLS_CHANNEL_PACKAGE_NAME));
    }

    @Test
    public void testSubscribeToChildChannelWithPackageNameMultipleResults()
        throws Exception {

        UserTestUtils.addVirtualization(user.getOrg());
        Server s = ServerTestUtils.createTestSystem(user);
        ChannelTestUtils.
            setupBaseChannelForVirtualization(s.getCreator(), s.getBaseChannel());
        // Repeat to ensure there's multiple child channels created:
        ChannelTestUtils.
            setupBaseChannelForVirtualization(s.getCreator(), s.getBaseChannel());

        int channelCountBefore = s.getChannels().size();
        try {
            ChannelManager.subscribeToChildChannelWithPackageName(user,
                s, ChannelManager.TOOLS_CHANNEL_PACKAGE_NAME);
            fail();
        }
        catch (MultipleChannelsWithPackageException e) {
            // expected
        }
        assertEquals(channelCountBefore, s.getChannels().size());
    }

    @Test
    public void testSubscribeToChildChannelWithPackageNameMultipleResultsAlreadySubbed()
        throws Exception {

        UserTestUtils.addVirtualization(user.getOrg());
        Server s = ServerTestUtils.createTestSystem(user);
        ChannelTestUtils.setupBaseChannelForVirtualization(s.getCreator(), s.getBaseChannel());
        // Repeat to ensure there's multiple child channels created:
        Channel[] chans = ChannelTestUtils.
        setupBaseChannelForVirtualization(s.getCreator(), s.getBaseChannel());

        // Subscribe to one set of the child channels but not the other, this should *not*
        // generate the multiple channels with package exception:
        s.addChannel(chans[0]);
        s.addChannel(chans[1]);
        TestUtils.saveAndReload(s);

        int channelCountBefore = s.getChannels().size();
        assertNotNull(ChannelManager.subscribeToChildChannelWithPackageName(user,
                    s, ChannelManager.TOOLS_CHANNEL_PACKAGE_NAME));
        assertEquals(channelCountBefore, s.getChannels().size());

    }

    @Test
    public void testsubscribeToChildChannelByOSProduct() throws Exception {
        UserTestUtils.addVirtualization(user.getOrg());
        Server s = ServerTestUtils.createTestSystem(user);
        ChannelTestUtils.setupBaseChannelForVirtualization(s.getCreator(),
                s.getBaseChannel());

        assertNotNull(ChannelManager.subscribeToChildChannelByOSProduct(user,
                s, ChannelManager.VT_OS_PRODUCT));

    }

    @Test
    public void testBaseChannelsInSet() throws Exception {
        // Get ourselves a system
        Server s = ServerTestUtils.createTestSystem(user);

        // insert sys into system-set
        RhnSetDecl.SYSTEMS.clear(user);
        RhnSet set = RhnSetDecl.SYSTEMS.get(user);
        set.addElement(s.getId());
        RhnSetManager.store(set);

        // ask for the base channels of all systems in the system-set for the test user
        DataResult<SystemsPerChannelDto> dr = ChannelManager.baseChannelsInSet(user);

        // should be one, with one system, and its name should be == the name of the
        // base-channel for the system we just created
        assertEquals(1, dr.size());
        SystemsPerChannelDto spc = dr.get(0);
        assertEquals(spc.getName(), s.getBaseChannel().getName());
        assertEquals(1, spc.getSystemCount());
    }

    @Test
    public void testListCompatibleBaseChannels() throws Exception {
        // Testing this is going to be a pain with our existing infrastructure

        // Create a server
        Server s = ServerTestUtils.createTestSystem(user);

        // Get its current base-channel
        Channel c = s.getBaseChannel();

        // Create a custom base channel
        Channel custom = ChannelTestUtils.createBaseChannel(user);
        custom.setOrg(user.getOrg());

        clearSsm();
        SsmManager.addServersToSsm(user, new String[] {s.getId().toString()});
        ChannelFactory.commitTransaction();
        commitHappened();

        // Ask for channels compatible with the new server's base
        List<EssentialChannelDto> compatibles = ChannelManager.listCompatibleBaseChannelsForChannel(user, c);

        // There should be two - we now list ALL custom-channelsl
        assertNotNull(compatibles);
        assertEquals(2, compatibles.size());

        boolean foundBase = false;
        boolean foundCustom = false;

        for (EssentialChannelDto ecd : compatibles) {
            foundBase |= c.getId().equals(ecd.getId());
            foundCustom |= custom.getId().equals(ecd.getId());
        }
        assertFalse(foundBase);
        assertTrue(foundCustom);
    }

    @Test
    public void testNormalizeRhelReleaseForMapping() {
        assertEquals("4.6.9", ChannelManager.normalizeRhelReleaseForMapping("5Server",
                "4.6.9"));
        assertEquals("5.0.0", ChannelManager.normalizeRhelReleaseForMapping("5Server",
        "5.0.0.9"));
    }

    @Test
    public void testFindCompatibleChildrenByOriginalChannel() throws Exception {
        // look for a cloned channel
        Channel parent = ChannelFactoryTest.createBaseChannel(user);
        Channel child = ChannelFactoryTest.createTestChannel(user);

        child.setParentChannel(parent);

        TestUtils.saveAndFlush(child);
        TestUtils.saveAndFlush(parent);
        TestUtils.flushAndEvict(child);

        Channel parent1 = ChannelFactoryTest.createTestClonedChannel(parent, user);
        Channel child1 = ChannelFactoryTest.createTestClonedChannel(child, user);

        child1.setParentChannel(parent1);

        TestUtils.saveAndFlush(child1);
        TestUtils.saveAndFlush(parent1);
        TestUtils.flushAndEvict(child1);

        Map<Channel, Channel> children = ChannelManager.
                                findCompatibleChildren(parent, parent1, user);

        assertNotEmpty(children.keySet());
        assertEquals(child, children.keySet().iterator().next());

        // look for a a clone of a cloned channel
        Channel parent2 = ChannelFactoryTest.createTestClonedChannel(parent1, user);
        Channel child2 = ChannelFactoryTest.createTestClonedChannel(child1, user);
        child2.setParentChannel(parent2);

        TestUtils.saveAndFlush(child2);
        TestUtils.saveAndFlush(parent2);
        TestUtils.flushAndEvict(child2);

        children = ChannelManager.
                findCompatibleChildren(parent, parent2, user);

        assertNotEmpty(children.keySet());
        assertEquals(child, children.keySet().iterator().next());
        assertEquals(child2, children.values().iterator().next());
    }

    @Test
    public void testFindCompatibleChildrenByParentProduct() throws Exception {
        ProductName pn = ChannelFactoryTest.createProductName();
        Channel parent = ChannelFactoryTest.createBaseChannel(user);
        Channel child = ChannelFactoryTest.createTestChannel(user);

        child.setParentChannel(parent);
        child.setProductName(pn);

        TestUtils.saveAndFlush(child);
        TestUtils.saveAndFlush(parent);
        TestUtils.flushAndEvict(child);

        Channel parent1 = ChannelFactoryTest.createBaseChannel(user);
        Channel child1 = ChannelFactoryTest.createTestChannel(user);

        child1.setParentChannel(parent1);
        child1.setProductName(pn);

        TestUtils.saveAndFlush(child1);
        TestUtils.saveAndFlush(parent1);
        TestUtils.flushAndEvict(child1);

        Map<Channel, Channel> children = ChannelManager.findCompatibleChildren(parent, parent1, user);

        assertNotEmpty(children.keySet());
        assertEquals(child, children.keySet().iterator().next());
        assertEquals(child1, children.values().iterator().next());

    }

    @Test
    public void testLookupDistChannelMap() throws Exception {
        Channel c = ChannelFactoryTest.createTestChannel(user);
        ProductName pn = new ProductName();
        pn.setLabel(TEST_OS);
        pn.setName(TEST_OS);
        HibernateFactory.getSession().save(pn);
        c.setProductName(pn);
        HibernateFactory.getSession().save(c);

        String release = MAP_RELEASE + TestUtils.randomString();
        ChannelTestUtils.addDistMapToChannel(c, TEST_OS, release);
        DistChannelMap dcm = ChannelManager.lookupDistChannelMapByPnReleaseArch(
                user.getOrg(), TEST_OS, release, c.getChannelArch());
        assertNotNull(dcm);
        assertEquals(c.getId(), dcm.getChannel().getId());
    }

    @Test
    public void testListCompatiblePackageArches() {
        String[] arches = {"channel-ia32", "channel-x86_64"};
        List<String> parches = ChannelManager.listCompatiblePackageArches(arches);
        assertTrue(parches.contains("i386"));
    }


    @Test
    public void testRemoveErrata() throws Exception {
        Channel c = ChannelFactoryTest.createTestChannel(user);
        List<Errata> errataList = new ArrayList<>();
        Errata e = ErrataFactoryTest.createTestErrata(user.getOrg().getId());
        errataList.add(e);
        ErrataFactory.addToChannel(errataList, c, user, false);

        e = (Errata) TestUtils.saveAndReload(e);

        assertTrue(e.getChannels().contains(c));

        Set<Long> eids = new HashSet<>();
        eids.add(e.getId());

        ChannelManager.removeErrata(c, eids, user);
        e = (Errata) TestUtils.saveAndReload(e);
        assertFalse(e.getChannels().contains(c));
        c = ChannelManager.lookupByLabel(user.getOrg(), c.getLabel());
        assertFalse(c.getErratas().contains(eids));
    }

    @Test
    public void testListErrataPackages() throws Exception {

        Channel c = ChannelFactoryTest.createBaseChannel(user);
        Errata e = ErrataFactoryTest.createTestErrata(user.getOrg().getId());

        Package bothP = PackageTest.createTestPackage(user.getOrg());
        Package channelP = PackageTest.createTestPackage(user.getOrg());
        Package errataP = PackageTest.createTestPackage(user.getOrg());


        c.addPackage(bothP);
        e.addPackage(bothP);

        c.addPackage(channelP);
        e.addPackage(errataP);

        c.addErrata(e);

        c = (Channel) TestUtils.saveAndReload(c);
        e = (Errata) TestUtils.saveAndReload(e);

        bothP = (Package) TestUtils.saveAndReload(bothP);


        List<PackageDto> list = ChannelManager.listErrataPackages(c, e);
        assertEquals(list.size(), 1);
        assertEquals(list.get(0).getId(), (bothP.getId()));


    }

    @Test
    public void testListErrataNeedingResync() throws Exception {

        user.addToGroup(AccessGroupFactory.CHANNEL_ADMIN);
        UserFactory.save(user);

        Channel ochan = ChannelFactoryTest.createTestChannel(user);
        Channel cchan = ChannelFactoryTest.createTestClonedChannel(ochan, user);

        Errata oe = ErrataFactoryTest.createTestErrata(null);
        ochan.addErrata(oe);

        List<Long> list = new ArrayList<>();
        list.add(cchan.getId());

        Long ceid = ErrataHelper.cloneErrataFaster(oe.getId(), user.getOrg());
        Errata ce = ErrataFactory.lookupById(ceid);
        ce = ErrataManager.addToChannels(ce, list, user);

        Package testPackage = PackageTest.createTestPackage(user.getOrg());
        oe.addPackage(testPackage);
        ochan.addPackage(testPackage);

        List<ErrataOverview> result = ChannelManager.listErrataNeedingResync(cchan, user);
        assertEquals(1, result.size());
        assertEquals(result.get(0).getId(), ce.getId());
    }

    /**
     * ChannelManager.listErrataNeedingResync should also list errata in case the advisoryStatus
     * of clone is different from the original.
     * @throws Exception
     */
    @Test
    public void testListErrataNeedingResyncRetracted() throws Exception {
        user.addToGroup(AccessGroupFactory.CHANNEL_ADMIN);
        UserFactory.save(user);

        Channel ochan = ChannelFactoryTest.createTestChannel(user);
        Channel cchan = ChannelFactoryTest.createTestClonedChannel(ochan, user);

        Errata oe = ErrataFactoryTest.createTestErrata(null);
        ochan.addErrata(oe);
        // let's also add an extra erratum to the original, but let's not clone it to the cloned channel
        // it must not appear in the result
        Errata notCloned = ErrataFactoryTest.createTestErrata(null);
        ochan.addErrata(notCloned);

        Long ceid = ErrataHelper.cloneErrataFaster(oe.getId(), user.getOrg());
        Errata ce = ErrataFactory.lookupById(ceid);
        ce = ErrataManager.addToChannels(ce, List.of(cchan.getId()), user);

        oe.setAdvisoryStatus(AdvisoryStatus.RETRACTED);
        notCloned.setAdvisoryStatus(AdvisoryStatus.RETRACTED);

        List<ErrataOverview> result = ChannelManager.listErrataNeedingResync(cchan, user);
        assertEquals(1, result.size());
        assertEquals(result.get(0).getId(), ce.getId());
    }

    @Test
    public void testListErrataPackagesForResync() throws Exception {

        user.addToGroup(AccessGroupFactory.CHANNEL_ADMIN);

        Channel ochan = ChannelFactoryTest.createTestChannel(user);
        Channel cchan = ChannelFactoryTest.createTestClonedChannel(ochan, user);

        Errata oe = ErrataFactoryTest.createTestErrata(null);
        ochan.addErrata(oe);

        List<Long> list = new ArrayList<>();
        list.add(cchan.getId());

        Long ceid = ErrataHelper.cloneErrataFaster(oe.getId(), user.getOrg());
        Errata ce = ErrataFactory.lookupById(ceid);
        ce = ErrataManager.addToChannels(ce, list, user);

        Package testPackage = PackageTest.createTestPackage(user.getOrg());
        oe.addPackage(testPackage);
        ochan.addPackage(testPackage);

        RhnSet set = RhnSetDecl.ERRATA_TO_SYNC.get(user);
        set.clear();
        set.add(ce.getId());
        RhnSetManager.store(set);

        List<PackageOverview> result = ChannelManager.listErrataPackagesForResync(
                                         cchan, user, set.getLabel());
        assertEquals(1, result.size());

        assertEquals(result.get(0).getId(), testPackage.getId());
    }

    @Test
    public void ensureForceBecomingCloneOfWorksOnClonedChannels() throws Exception {
        user.addToGroup(AccessGroupFactory.CHANNEL_ADMIN);
        Channel origCh = ChannelFactoryTest.createTestChannel(user);
        Channel clonedCh = ChannelFactoryTest.createTestClonedChannel(origCh, user);

        assertTrue(clonedCh.asCloned().isPresent());
        assertEquals(origCh, clonedCh.asCloned().orElseThrow().getOriginal());

        Channel substituteOrigCh = ChannelFactoryTest.createTestChannel(user);
        ChannelManager.forceBecomingCloneOf(clonedCh, substituteOrigCh);

        assertTrue(clonedCh.asCloned().isPresent());
        assertEquals(substituteOrigCh, clonedCh.asCloned().orElseThrow().getOriginal());
    }

    @Test
    public void ensureForceBecomingCloneOfWorksOnRegularChannels() throws Exception {
        user.addToGroup(AccessGroupFactory.CHANNEL_ADMIN);
        Channel regularCh = ChannelFactoryTest.createTestChannel(user);

        assertFalse(regularCh.asCloned().isPresent());

        Channel origCh = ChannelFactoryTest.createTestChannel(user);
        ChannelManager.forceBecomingCloneOf(regularCh, origCh);
        regularCh = HibernateFactory.reload(regularCh);

        assertTrue(regularCh.asCloned().isPresent());
        assertEquals(origCh, regularCh.asCloned().orElseThrow().getOriginal());
    }

    /**
     * Clears the list of servers in the SSM.
     */
    private void clearSsm() {
        RhnSet set = RhnSetDecl.SYSTEMS.get(user);
        set.clear();
        RhnSetManager.store(set);
    }

    private TaskomaticApi getTaskomaticApi() throws TaskomaticApiException {
        if (taskomaticApi == null) {
            taskomaticApi = mockContext.mock(TaskomaticApi.class);
            mockContext.checking(new Expectations() {
                {
                    allowing(taskomaticApi).scheduleActionExecution(with(any(Action.class)));
                }
            });
        }

        return taskomaticApi;
    }
}
