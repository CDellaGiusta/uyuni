/*
 * Copyright (c) 2009--2016 Red Hat, Inc.
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
package com.redhat.rhn.manager.rhnpackage.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.redhat.rhn.common.db.datasource.DataResult;
import com.redhat.rhn.common.db.datasource.ModeFactory;
import com.redhat.rhn.common.db.datasource.WriteMode;
import com.redhat.rhn.common.hibernate.HibernateFactory;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.ChannelFactory;
import com.redhat.rhn.domain.channel.test.ChannelFactoryTest;
import com.redhat.rhn.domain.errata.Errata;
import com.redhat.rhn.domain.errata.ErrataFactory;
import com.redhat.rhn.domain.errata.test.ErrataFactoryTest;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.rhnpackage.Package;
import com.redhat.rhn.domain.rhnpackage.PackageArch;
import com.redhat.rhn.domain.rhnpackage.PackageCapability;
import com.redhat.rhn.domain.rhnpackage.PackageEvr;
import com.redhat.rhn.domain.rhnpackage.PackageEvrFactory;
import com.redhat.rhn.domain.rhnpackage.PackageExtraTagsKeys;
import com.redhat.rhn.domain.rhnpackage.PackageFactory;
import com.redhat.rhn.domain.rhnpackage.PackageName;
import com.redhat.rhn.domain.rhnpackage.test.PackageCapabilityTest;
import com.redhat.rhn.domain.rhnpackage.test.PackageEvrFactoryTest;
import com.redhat.rhn.domain.rhnpackage.test.PackageNameTest;
import com.redhat.rhn.domain.rhnpackage.test.PackageTest;
import com.redhat.rhn.domain.role.RoleFactory;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.server.test.ServerFactoryTest;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.dto.PackageDto;
import com.redhat.rhn.frontend.dto.PackageListItem;
import com.redhat.rhn.frontend.dto.PackageOverview;
import com.redhat.rhn.frontend.dto.SsmUpgradablePackageListItem;
import com.redhat.rhn.frontend.dto.UpgradablePackageListItem;
import com.redhat.rhn.frontend.listview.PageControl;
import com.redhat.rhn.manager.channel.ChannelManager;
import com.redhat.rhn.manager.errata.cache.test.ErrataCacheManagerTest;
import com.redhat.rhn.manager.kickstart.tree.BaseTreeEditOperation;
import com.redhat.rhn.manager.rhnpackage.PackageManager;
import com.redhat.rhn.manager.system.SystemManager;
import com.redhat.rhn.taskomatic.task.repomd.SimpleAttributesImpl;
import com.redhat.rhn.taskomatic.task.repomd.SimpleContentHandler;
import com.redhat.rhn.testing.BaseTestCaseWithUser;
import com.redhat.rhn.testing.ChannelTestUtils;
import com.redhat.rhn.testing.ServerTestUtils;
import com.redhat.rhn.testing.TestUtils;

import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.hibernate.Session;
import org.hibernate.query.Query;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * PackageManagerTest
 */
public class PackageManagerTest extends BaseTestCaseWithUser {

    @Test
    public void testSystemPackageList() throws Exception {
        // need a system
        // need to add packages to that system
        // then need to query those values
        PageControl pc = new PageControl();
        pc.setIndexData(false);
        pc.setStart(1);

        user.addPermanentRole(RoleFactory.ORG_ADMIN);

        Server server = ServerFactoryTest.createTestServer(user, true);
        PackageManagerTest.addPackageToSystemAndChannel(
                "test-package-name" + TestUtils.randomString(), server,
                ChannelFactoryTest.createTestChannel(user));

        DataResult dr = PackageManager.systemPackageList(server.getId(), pc);
        assertNotNull(dr);
        assertEquals(1, dr.size());

        for (Object o : dr) {
            assertInstanceOf(PackageListItem.class, o);
        }
    }

    @Test
    public void testSystemPackageListMulti() throws Exception {
        // Test that the package id comes from a package of an assigned channel
        PageControl pc = new PageControl();
        pc.setIndexData(false);
        pc.setStart(1);

        user.addPermanentRole(RoleFactory.ORG_ADMIN);

        Server server = ServerFactoryTest.createTestServer(user, true);

        // create 2 packages with same NEVRA in different channels
        PackageArch parch = HibernateFactory.getSession().createNativeQuery("""
                SELECT p.* from rhnPackageArch as p WHERE p.id = :id
                """, PackageArch.class).setParameter("id", 100L).getSingleResult();

        PackageName pname = PackageNameTest.createTestPackageName();
        PackageEvr pevr = PackageEvrFactoryTest.createTestPackageEvr(parch.getArchType().getPackageType());

        Package p1 = new Package();
        PackageTest.populateTestPackage(p1, user.getOrg(), pname, pevr, parch);
        TestUtils.saveAndFlush(p1);

        Package p2 = new Package();
        PackageTest.populateTestPackage(p2, user.getOrg(), pname, pevr, parch);
        TestUtils.saveAndFlush(p2);

        Channel c1 = ChannelFactoryTest.createTestChannel(user);
        Channel c2 = ChannelFactoryTest.createTestChannel(user);
        PackageTest.addPackageToChannelNewestPackage(p1, c1);
        PackageTest.addPackageToChannelNewestPackage(p2, c2);

        PackageManagerTest.associateSystemToPackage(server, p1);
        server = SystemManager.subscribeServerToChannel(user, server, c1);

        DataResult dr = PackageManager.systemPackageList(server.getId(), pc);
        assertNotNull(dr);
        assertEquals(1, dr.size());

        for (Object o : dr) {
            assertInstanceOf(PackageListItem.class, o);
            PackageListItem pli = (PackageListItem) o;
            assertEquals(p1.getId(), pli.getPackageId());
        }
    }

    @Test
    public void testGuestimateChannelInvalidPackage() {
        // guestimatePackageByChannel should return null if it
        // can't find a package, not throw an exception.
        try {
            assertNull(PackageManager.guestimatePackageByChannel(
                    10000L, 100L, 100L, null));
        }
        catch (Exception e) {
            fail("method should return null");
        }
    }

    @Test
    public void testGuestimateHandlesNullArchId() {
        PackageListItem pli = PackageListItem.parse("10000|1000");
        assertNull(pli.getIdThree());
        assertNull(PackageManager.guestimatePackageBySystem(10000L, 100L, 100L,
                pli.getIdThree(), null));
    }

    @Test
    public void testGuestimateInvalidPackage() {
        // guestimatePackageBySystem should return null if it
        // can't find a package, not throw an exception.
        try {
            assertNull(PackageManager.guestimatePackageBySystem(10000L, 100L, 100L,
                    0L, null));
        }
        catch (Exception e) {
            fail("method should return null");
        }
    }

    @Test
    public void testUpgradable() throws Exception {
        Map<String, Object> info = ErrataCacheManagerTest.createServerNeededCache(user, ErrataFactory.ERRATA_TYPE_BUG);
        Server s = (Server) info.get("server");
        Package p = (Package) info.get("package");
        p = TestUtils.saveAndReload(p);

        DataResult<UpgradablePackageListItem> dr =
            PackageManager.upgradable(s.getId(), null);
        assertFalse(dr.isEmpty());
        boolean containsSamePackage = false;
        for (UpgradablePackageListItem item : dr) {
            if (p.getPackageName().getName().equals(item.getName())) {
                containsSamePackage = true;
            }
            assertEquals(3, item.getIdCombo().split("\\|").length);
        }
        assertTrue(containsSamePackage);
    }

    @Test
    public void testSystemAvailablePackages() throws Exception {
        // need a system
        // need to add packages to that system
        // then need to query those values
        PageControl pc = new PageControl();
        pc.setIndexData(false);
        pc.setStart(1);

        user.addPermanentRole(RoleFactory.ORG_ADMIN);

        Server server = ServerFactoryTest.createTestServer(user, true);

        PackageManagerTest.addPackageToSystemAndChannel(
                "test-package-name" + TestUtils.randomString(), server,
                ChannelFactoryTest.createTestChannel(user));

        // hard code for now.
        DataResult dr = PackageManager.systemAvailablePackages(server.getId(), pc);
        assertNotNull(dr);
        assertEquals(0, dr.size());

        for (Object o : dr) {
            assertInstanceOf(PackageListItem.class, o);
        }
    }

    /**
     * This method inserts a record into the rhnServerPackage mapping
     * table to associate a given Server with a particular Package.
     * The web code doesn't actually create any of these records, but
     * this will be needed by the backend code.
     * @param srvr Server to associate with the packages
     * @param p The package
     */
    public static void associateSystemToPackage(Server srvr, Package p) {
        try {
            WriteMode m =
                ModeFactory.
                getWriteMode("test_queries", "insert_into_rhnServerPackage_with_arch");
            Map<String, Object> params = new HashMap<>();
            params.put("server_id", srvr.getId());
            params.put("pn_id", p.getPackageName().getId());
            params.put("evr_id", p.getPackageEvr().getId());
            params.put("arch_id", p.getPackageArch().getId());

            m.executeUpdate(params);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * This method inserts a record into the rhnServerPackage mapping
     * table to associate a given Server with a particular Package.
     * The web code doesn't actually create any of these records, but
     * this will be needed by the backend code.
     * @param srvr Server to associate with the packages
     * @param p The package
     */
    public static void associateSystemToPackageWithArch(Server srvr, Package p) {
        try {
            WriteMode m = ModeFactory.getWriteMode("test_queries",
                "insert_into_rhnServerPackage_with_arch");

            Map<String, Long> params = new HashMap<>(4);
            params.put("server_id", srvr.getId());
            params.put("pn_id", p.getPackageName().getId());
            params.put("evr_id", p.getPackageEvr().getId());
            params.put("arch_id", p.getPackageArch().getId());

            m.executeUpdate(params);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Add a new Package to the specified Channel and associate the system
     * with it.
     * @param packageName the name of the package to add
     * @param s the system to associate with the package
     * @param c The channel to which to add the package
     * @return the new package
     */
    public static Package addPackageToSystemAndChannel(String packageName,
            Server s, Channel c) {
        Package retval = addPackageToChannel(packageName, c);
        PackageManagerTest.associateSystemToPackage(s, retval);
        return retval;
    }

    /**
     * Create a package with the given name and add it to the given channel.
     * If a package by that name already exists, this simply returns that package.
     * @param packageName The name of the package to create.
     * @param c The channel to which to add the package
     * @return The package with that name in the channel.
     */
    public static Package addPackageToChannel(String packageName, Channel c) {

        PackageName pn = PackageFactory.lookupOrCreatePackageByName(packageName);
        if (pn == null) {
            pn = PackageNameTest.createTestPackageName();
            pn.setName(packageName);
        }

        Long existingId = ChannelManager.getLatestPackageEqual(c.getId(), packageName);

        if (existingId != null) {
            return PackageFactory.lookupByIdAndOrg(existingId, c.getOrg());
        }

        //existingId =
        Session session = HibernateFactory.getSession();
        Query query = session.createQuery(
                "from Package as " +
                "package where package.org.id = " + c.getOrg().getId() +
                " and package.packageName.id = " + pn.getId());
        List packages = query.list();
        Package retval = null;
        if (packages != null && !packages.isEmpty()) {
            retval = (Package) packages.get(0);
        }
        else {
            retval = PackageTest.createTestPackage(c.getOrg());
        }

        retval.setPackageName(pn);
        TestUtils.saveAndFlush(retval);
        PackageTest.addPackageToChannelNewestPackage(retval, c);

        return retval;
    }

    @Test
    public void testCreateLotsofPackagesInChannel() throws Exception {
        String rand = TestUtils.randomString();
        Channel c = ChannelTestUtils.createTestChannel(user);
        for (int i = 0; i < 10; i++) {
            addPackageToChannel(rand, c);
        }
    }

    @Test
    public void testPossiblePackagesForPushingIntoChannel() throws Exception {
        Errata e = ErrataFactoryTest.createTestErrata(user.getOrg().getId());
        Channel c = ChannelTestUtils.createTestChannel(user);
        DataResult dr = PackageManager.possiblePackagesForPushingIntoChannel(c.getId(),
                e.getId(), null);
        assertFalse(dr.isEmpty());
   }


    @Test
    public void testGetServerNeededUpdatePackageByName() throws Exception {
        user.addPermanentRole(RoleFactory.ORG_ADMIN);
        Server s = ServerFactoryTest.createTestServer(user);
        Channel c = ChannelFactoryTest.createTestChannel(user);
        addPackageToSystemAndChannel("some-test-package", s, c);
        // Not enough time actually test the results of this query for now
        // Just testing that it runs without SQL error. -mmccune
        assertNull(PackageManager.
                getServerNeededUpdatePackageByName(s.getId(), "some-test-package"));
    }

    @Test
    public void testPackageIdsInSet() {
        DataResult<PackageOverview> dr = PackageManager.packageIdsInSet(user, "packages_to_add",
                                                       new PageControl());
        assertNotNull(dr);
    }

    /**
     * Add the up2date package to a system and a channel.  Version
     * should be specified such as "2.9.0"
     *
     * @param userIn the user
     * @param s the system
     * @param version the version
     * @param c the channel
     * @return the updated or added package
     * @throws Exception something bad happened
     */
    public static Package addUp2dateToSystemAndChannel(User userIn, Server s,
            String version, Channel c) throws Exception {

        Package p = null;
        PackageName pn = PackageFactory.lookupOrCreatePackageByName("up2date");
        if (pn != null) {
            List<Package> packages = PackageFactory.listPackagesByPackageName(pn);
            for (Package innerp : packages) {
                PackageEvr evr = innerp.getPackageEvr();
                if (evr != null &&
                        evr.getVersion().equals(version)) {
                    p = innerp;
                }
            }
        }
        if (p == null) {
            p = PackageManagerTest.
            addPackageToSystemAndChannel("up2date", s, c);
            PackageEvr pevr = PackageEvrFactory.lookupOrCreatePackageEvr("0",
                    version, "0", s.getPackageType());
            p.setPackageEvr(pevr);
            TestUtils.saveAndFlush(p);
        }
        else {
            PackageManagerTest.associateSystemToPackage(s, p);
        }


        return p;
    }

    /**
     * Add a kickstart package with the given name to the given channel.
     * @param packageName the name of the package to add
     * @param channel the channel to add the package to
     */
    public static void addKickstartPackageToChannel(String packageName, Channel channel) {
        PackageCapability kickstartCapability =  findOrCreateKickstartCapability();
        Package kickstartPkg =
            PackageManagerTest.addPackageToChannel(packageName, channel);

        WriteMode m = ModeFactory.getWriteMode("test_queries",
                "insert_into_rhnPackageProvides");
        Map<String, Object> params = new HashMap<>();
        params.put("pkg_id", kickstartPkg.getId());
        params.put("capability_id", kickstartCapability.getId());
        params.put("sense_id", 8);
        m.executeUpdate(params);

        // Repeast for another sense:
        params.put("sense_id", 268435464);
        m.executeUpdate(params);
    }

    /**
     * Find the kickstart package capability if it exists, create it otherwise.
     * @return The kickstart package capability.
     */
    private static PackageCapability findOrCreateKickstartCapability() {
        Session session = HibernateFactory.getSession();
        Query query = session.createQuery(
                "from PackageCapability where name = :capability");
        query.setParameter("capability", BaseTreeEditOperation.KICKSTART_CAPABILITY);
        List results = query.list();

        // Multiple results could be returned for this capability,
        // take the first:
        if (results.size() >= 1) {
            return (PackageCapability)results.get(0);
        }

        return PackageCapabilityTest.createTestCapability(
                BaseTreeEditOperation.KICKSTART_CAPABILITY);
    }

    @Test
    public void testPackageNameOverview() {
        String packageName = "kernel";
        String[] channelarches = {"channel-ia32", "channel-x86_64"};
        DataResult dr = PackageManager.lookupPackageNameOverview(
                user.getOrg(), packageName, channelarches);

        assertNotNull(dr);
    }

    @Test
    public void testLookupPackageForChannelFromChannel() throws Exception {
        Channel channel1 = ChannelFactoryTest.createTestChannel(user);
        Channel channel2 = ChannelFactoryTest.createTestChannel(user);

        Package pack = PackageTest.createTestPackage(null);
        channel1.addPackage(pack);

        List<PackageOverview> test = PackageManager.lookupPackageForChannelFromChannel(channel1.getId(),
                channel2.getId());
        assertEquals(1, test.size());
        PackageOverview packOver = test.get(0);
        assertEquals(pack.getId(), packOver.getId());

        channel2.addPackage(pack);
        test = PackageManager.lookupPackageForChannelFromChannel(channel1.getId(),
                channel2.getId());
        assertTrue(test.isEmpty());
    }

    @Test
    public void testLookupCustomPackagesForChannel() throws Exception {
        Channel channel1 = ChannelFactoryTest.createTestChannel(user);
        Package pack = PackageTest.createTestPackage(user.getOrg());
        List<PackageOverview> test = PackageManager.lookupCustomPackagesForChannel(
                channel1.getId(), user.getOrg().getId());

        assertEquals(1, test.size());
        PackageOverview packOver = test.get(0);
        assertEquals(pack.getId(), packOver.getId());

        channel1.addPackage(pack);
        test = PackageManager.lookupCustomPackagesForChannel(
                channel1.getId(), user.getOrg().getId());

        assertTrue(test.isEmpty());
    }

    @Test
    public void testListOrphanPackages() throws Exception {
        Channel channel1 = ChannelFactoryTest.createTestChannel(user);
        Package pack = PackageTest.createTestPackage(user.getOrg());
        List<PackageOverview> test = PackageManager.listOrphanPackages(user.getOrg().getId(), false);

        assertEquals(1, test.size());
        PackageOverview packOver = test.get(0);
        assertEquals(pack.getId(), packOver.getId());

        channel1.addPackage(pack);
        test = PackageManager.listOrphanPackages(user.getOrg().getId(), false);

        assertTrue(test.isEmpty());
        PackageTest.createTestPackage(user.getOrg());
        test = PackageManager.listOrphanPackages(user.getOrg().getId(), false);

        assertEquals(1, test.size());

    }

    @Test
    public void testUpgradablePackagesFromServerSet() throws Exception {
        // Setup
        Org org = user.getOrg();

        //   Create the server and add to the SSM
        Server server = ServerTestUtils.createTestSystem(user);
        ServerTestUtils.addServersToSsm(user, server.getId());

        //   Create upgraded package EVR so package will show up from the query
        PackageEvr upgradedPackageEvr =
            PackageEvrFactory.lookupOrCreatePackageEvr("1", "1.0.0", "2", server.getPackageType());
        upgradedPackageEvr =
            (PackageEvr)TestUtils.saveAndReload(upgradedPackageEvr);

        ServerTestUtils.populateServerErrataPackages(org, server,
            upgradedPackageEvr, ErrataFactory.ERRATA_TYPE_SECURITY);
        ServerTestUtils.populateServerErrataPackages(org, server,
            upgradedPackageEvr, ErrataFactory.ERRATA_TYPE_BUG);

        // Test
        DataResult<SsmUpgradablePackageListItem> result = PackageManager.upgradablePackagesFromServerSet(user);

        assertNotNull(result);
        assertEquals(2, result.size());
    }

    @Test
    public void testDeletePackages() {
        // Configuration
        final int numPackagesToDelete = 50;

        // Setup
        user.addPermanentRole(RoleFactory.ORG_ADMIN);

        Set<Long> doomedPackageIds = new HashSet<>(numPackagesToDelete);
        for (int ii = 0; ii < numPackagesToDelete; ii++) {
            Package pack = PackageTest.createTestPackage(user.getOrg());
            doomedPackageIds.add(pack.getId());
        }

        int numPackagesBeforeDelete =
            PackageFactory.lookupOrphanPackages(user.getOrg()).size();
        assertTrue(numPackagesBeforeDelete >= numPackagesToDelete);


        // Test
        PackageManager.deletePackages(doomedPackageIds, user);

        // Verify
        int numPackagesAfterDelete =
        PackageFactory.lookupOrphanPackages(user.getOrg()).size();
                assertEquals(numPackagesBeforeDelete - numPackagesToDelete,
                             numPackagesAfterDelete);

    }


    protected SimpleContentHandler getTemporaryHandler(OutputStream st) {
        OutputFormat of = new OutputFormat();
        of.setPreserveSpace(true);
        of.setOmitXMLDeclaration(true);
        XMLSerializer tmpSerial = new XMLSerializer(st, of);
        return new SimpleContentHandler(tmpSerial);
    }


    @Test
    public void testRepodata() throws Exception {

        OutputStream st = new ByteArrayOutputStream();
        SimpleContentHandler tmpHandler = getTemporaryHandler(st);


        SimpleAttributesImpl attr = new SimpleAttributesImpl();
        attr.addAttribute("type", "rpm");
        tmpHandler.startDocument();

        tmpHandler.startElement("package", attr);

        SimpleAttributesImpl secattr = new SimpleAttributesImpl();
        attr.addAttribute("bar", "&>><<");
        tmpHandler.startElement("foo", secattr);
        tmpHandler.addCharacters("&&&&");
        tmpHandler.endElement("foo");

        tmpHandler.endElement("package");
        tmpHandler.endDocument();

        String test = st.toString();
        System.out.println(test);

        Package p = PackageTest.createTestPackage(user.getOrg());
        Channel c = ChannelFactoryTest.createTestChannel(user);
        c.addPackage(p);
        ChannelFactory.save(c);

        PackageManager.createRepoEntrys(c.getId());

        PackageManager.updateRepoPrimary(p.getId(), test);
        DataResult dr = PackageManager.getRepoData(p.getId());
        PackageDto dto = (PackageDto) dr.get(0);
        String prim = dto.getPrimaryXml();
        assertEquals(prim, test);
    }

    public static PackageExtraTagsKeys createExtraTagKey(String name) {
        PackageExtraTagsKeys tag1 = new PackageExtraTagsKeys();
        tag1.setName(name);
        HibernateFactory.getSession().save(tag1);
        return tag1;
    }
}
