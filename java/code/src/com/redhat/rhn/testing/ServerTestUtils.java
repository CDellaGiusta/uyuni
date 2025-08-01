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
package com.redhat.rhn.testing;

import com.redhat.rhn.GlobalInstanceHolder;
import com.redhat.rhn.common.hibernate.HibernateFactory;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.errata.Errata;
import com.redhat.rhn.domain.errata.test.ErrataFactoryTest;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.rhnpackage.Package;
import com.redhat.rhn.domain.rhnpackage.PackageArch;
import com.redhat.rhn.domain.rhnpackage.PackageEvr;
import com.redhat.rhn.domain.rhnpackage.PackageEvrFactory;
import com.redhat.rhn.domain.rhnpackage.PackageName;
import com.redhat.rhn.domain.rhnpackage.test.PackageTest;
import com.redhat.rhn.domain.rhnset.RhnSet;
import com.redhat.rhn.domain.rhnset.SetCleanup;
import com.redhat.rhn.domain.role.RoleFactory;
import com.redhat.rhn.domain.server.InstalledPackage;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.server.ServerConstants;
import com.redhat.rhn.domain.server.ServerFactory;
import com.redhat.rhn.domain.server.ServerGroupType;
import com.redhat.rhn.domain.server.VirtualInstance;
import com.redhat.rhn.domain.server.test.MinionServerFactoryTest;
import com.redhat.rhn.domain.server.test.ServerFactoryTest;
import com.redhat.rhn.domain.server.test.VirtualInstanceManufacturer;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.manager.entitlement.EntitlementManager;
import com.redhat.rhn.manager.errata.cache.ErrataCacheManager;
import com.redhat.rhn.manager.rhnpackage.PackageManager;
import com.redhat.rhn.manager.rhnset.RhnSetDecl;
import com.redhat.rhn.manager.rhnset.RhnSetManager;
import com.redhat.rhn.manager.system.entitling.SystemEntitlementManager;

import org.hibernate.Session;

import java.util.Set;


/**
 * SystemTestUtils
 */
public class ServerTestUtils {

    private static final String REDHAT_RELEASE = "redhat-release";
    private static final Long I386_PACKAGE_ARCH_ID = 101L;

    private ServerTestUtils() {
    }

    /**
     * Create a test system that has a base channel
     *
     * @param creator who owns the server
     * @return Server created
     * @throws Exception if error
     */
    public static Server createTestSystem(User creator) throws Exception {
        return createTestSystem(creator, ServerConstants.getServerGroupTypeSaltEntitled());
    }

    /**
     * Create a test system that has a base channel in a certain server group
     * type.
     * @param creator who owns the server
     * @param serverGroupType the server group type
     * @return Server created
     * @throws Exception if error
     */
    public static Server createTestSystem(User creator, ServerGroupType serverGroupType)
        throws Exception {
        Server retval = ServerFactoryTest.createTestServer(creator, true, serverGroupType);
        Channel baseChannel = ChannelTestUtils.createBaseChannel(creator);
        retval.addChannel(baseChannel);
        ServerFactory.save(retval);
        retval = TestUtils.reload(retval);
        return retval;
    }

    /**
     * Adds a simulated redhat-release rpm to the given server.
     * @param user User performing the action.
     * @param addTo Server to add to.
     * @param version redhat-release version. (i.e. 5Server)
     * @param release redhat-release release. (i.e. 5.1.0)
     * @return Reloaded server object.
     */
    public static Server addRedhatReleasePackageToServer(User user, Server addTo,
            String version, String release) {

        InstalledPackage testInstPack = new InstalledPackage();
        String epoch = null;
        PackageEvr evr = PackageEvrFactory.lookupOrCreatePackageEvr(epoch, version,
                release, addTo.getPackageType());
        testInstPack.setEvr(evr);

        PackageArch parch = HibernateFactory.getSession().createNativeQuery("""
                SELECT p.* from rhnPackageArch as p WHERE p.id = :id
                """, PackageArch.class).setParameter("id", I386_PACKAGE_ARCH_ID).getSingleResult();

        testInstPack.setArch(parch);

        PackageName redhatRelease = PackageManager.lookupPackageName(REDHAT_RELEASE);
        if (redhatRelease == null) {
            redhatRelease = new PackageName();
            redhatRelease.setName(REDHAT_RELEASE);
            TestUtils.saveAndFlush(redhatRelease);
        }

        testInstPack.setName(redhatRelease);
        testInstPack.setServer(addTo);
        Set<InstalledPackage> serverPackages = addTo.getPackages();
        serverPackages.add(testInstPack);

        ServerFactory.save(addTo);
        return TestUtils.reload(addTo);
    }

    /**
     * Create a test System with a new user/org as well.
     * @return Server created
     * @throws Exception if error
     */
    public static Server createTestSystem() throws Exception {
        return createTestSystem(UserTestUtils.findNewUser());
    }

    /**
     * Create a system with associated guest systems associated with it.
     *
     * @param user to own system
     * @param numberOfGuests number of guests to create
     * @param systemEntitlementManager to manage entitlements
     * @return Server with guest.
     * @throws Exception if error
     */
    public static Server createVirtHostWithGuests(User user, int numberOfGuests,
                                                  SystemEntitlementManager systemEntitlementManager)
        throws Exception {
        return createVirtHostWithGuests(user, numberOfGuests, true, systemEntitlementManager);
    }

    /**
     * Create a system with associated guest systems associated with it.
     *
     * @param user to own system
     * @param numberOfGuests number of guests to create
     * @param salt true to create a salt-managed systems
     * @param systemEntitlementManager to manage entitlements
     * @return Server with guest.
     * @throws Exception if error
     */
    public static Server createVirtHostWithGuests(User user, int numberOfGuests, boolean salt,
                                                  SystemEntitlementManager systemEntitlementManager)
        throws Exception {
        user.addPermanentRole(RoleFactory.ORG_ADMIN);
        TestUtils.saveAndFlush(user);
        Server s = null;
        if (salt) {
            s = MinionServerFactoryTest.createTestMinionServer(user);
            Channel baseChannel = ChannelTestUtils.createBaseChannel(user);
            s.addChannel(baseChannel);
        }
        else {
            s = createTestSystem(user, ServerConstants.getServerGroupTypeEnterpriseEntitled());
        }

        // Lets give the org/server virt.
        UserTestUtils.addVirtualization(user.getOrg());
        ServerTestUtils.addVirtualization(user, s);
        systemEntitlementManager.addEntitlementToServer(s, EntitlementManager.VIRTUALIZATION);

        for (int i = 0; i < numberOfGuests; i++) {
            VirtualInstance vi = new VirtualInstanceManufacturer(user).newRegisteredGuestWithoutHost(salt);
            vi.setConfirmed((long) 0);
            s.addGuest(vi);
        }

        return s;
    }

    /**
     * Add a new Server as a guest of the passed in Server.
     * @param user adding
     * @param server to add too
     * @throws Exception if err
     */
    public static void addGuestToServer(User user, Server server) throws Exception {
        VirtualInstance vi = new VirtualInstanceManufacturer(user).
            newRegisteredGuestWithoutHost();

        server.addGuest(vi);
    }


    /**
     * Add virtualization to the server passed in.  Will setup the base channel and child
     * channels with the right packages.
     * @param user user
     * @param s server
     * @throws Exception fi error
     */
    public static void addVirtualization(User user, Server s) throws Exception {
        ChannelTestUtils.setupBaseChannelForVirtualization(user, s.getBaseChannel());
    }

    /**
     * Create virthostwithguest
     * @param systemEntitlementManager to manage entitlements
     * @return Server with a guest
     * @throws Exception if error
     */
    public static Server createVirtHostWithGuest(SystemEntitlementManager systemEntitlementManager) throws Exception {
        return createVirtHostWithGuests(UserTestUtils.findNewUser(), 1, systemEntitlementManager);
    }

    /**
     * Create virt host with guests.
     * @param numberOfGuests Number of guests to create on this host.
     * @param systemEntitlementManager to manage entitlements
     * @return Server with a guest
     * @throws Exception if error
     */
    public static Server createVirtHostWithGuests(int numberOfGuests, SystemEntitlementManager systemEntitlementManager)
            throws Exception {
        return createVirtHostWithGuests(UserTestUtils.findNewUser(), numberOfGuests, systemEntitlementManager);
    }

    /**
     * Creates two packages and errata agains the specified server. An installed package
     * with the default EVR is created and installed to the server. The newer package
     * is created with the given EVR and is the package associated with the errata.
     *
     * @param org user's organization
     * @param server wher the packages will be installed
     * @param upgradedPackageEvr used as the EVR for the errata package
     * @param errataType type of errata to create
     * @return the original installed package (i.e. not the upgraded version)
     * @throws Exception if anything goes wrong writing to the DB
     */
    public static Package populateServerErrataPackages(Org org, Server server,
                                                       PackageEvr upgradedPackageEvr,
                                                       String errataType)
        throws Exception {

        Errata errata = ErrataFactoryTest.createTestErrata(org.getId());
        errata.setAdvisoryType(errataType);
        TestUtils.saveAndFlush(errata);

        Package installedPackage = PackageTest.createTestPackage(org);
        TestUtils.saveAndFlush(installedPackage);

        Session session = HibernateFactory.getSession();
        session.flush();

        Package upgradedPackage = PackageTest.createTestPackage(org);
        upgradedPackage.setPackageName(installedPackage.getPackageName());
        upgradedPackage.setPackageEvr(upgradedPackageEvr);
        TestUtils.saveAndFlush(upgradedPackage);

        ErrataCacheManager.insertNeededErrataCache(
                server.getId(), errata.getId(), installedPackage.getId());

        return installedPackage;
    }

    /**
     * Adds the servers identified by the given server IDs to the SSM.
     *
     * @param user      represents the logged in user
     * @param serverIds list of servers to add to the SSM
     */
    public static void addServersToSsm(User user, Long... serverIds) {
        RhnSet ssmSet = RhnSetManager.findByLabel(user.getId(),
        RhnSetDecl.SYSTEMS.getLabel(), SetCleanup.NOOP);

        if (ssmSet == null) {
            ssmSet = RhnSetManager.createSet(user.getId(),
                RhnSetDecl.SYSTEMS.getLabel(), SetCleanup.NOOP);
        }

        assert ssmSet != null;

        for (Long serverId : serverIds) {
            ssmSet.addElement(serverId);
        }

        RhnSetManager.store(ssmSet);

        ssmSet = RhnSetManager.findByLabel(user.getId(),
            RhnSetDecl.SYSTEMS.getLabel(), SetCleanup.NOOP);
        assert ssmSet != null;
    }

    /**
     * Creates a new foreign system.
     *
     * @param user the user
     * @param digitalServerId the system digital server id
     * @return the newly created foreign system
     * @throws Exception if server creation goes wrong
     */
    public static Server createForeignSystem(User user, String digitalServerId)
            throws Exception {
        Server existingHost = ServerTestUtils.createTestSystem(user,
                ServerConstants.getServerGroupTypeForeignEntitled());
        existingHost.setName(TestUtils.randomString());
        existingHost.setDigitalServerId(digitalServerId);
        GlobalInstanceHolder.SYSTEM_ENTITLEMENT_MANAGER.setBaseEntitlement(existingHost,
                EntitlementManager.getByName("foreign_entitled"));
        ServerFactory.save(existingHost);
        return existingHost;
    }
}
