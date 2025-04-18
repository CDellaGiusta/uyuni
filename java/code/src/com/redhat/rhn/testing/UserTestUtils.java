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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redhat.rhn.common.hibernate.LookupException;
import com.redhat.rhn.common.localization.LocalizationService;
import com.redhat.rhn.domain.access.AccessGroup;
import com.redhat.rhn.domain.access.AccessGroupFactory;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.org.OrgFactory;
import com.redhat.rhn.domain.role.Role;
import com.redhat.rhn.domain.role.RoleFactory;
import com.redhat.rhn.domain.server.EntitlementServerGroup;
import com.redhat.rhn.domain.server.ServerConstants;
import com.redhat.rhn.domain.user.Address;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.domain.user.UserFactory;
import com.redhat.rhn.manager.user.UserManager;

import java.util.List;

/**
 * A class that allows us to easily create test users.
 */
public class UserTestUtils  {
    // static class
    private UserTestUtils() { }

    public static final String TEST_PASSWORD = "password";

    /**
     * Creates a new Org with the given orgName.
     * The current time is appended to the given orgName.
     * @param orgName Name of org.
     * @return long The Org id.
     */
    public static Long createOrg(String orgName) {
        return createNewOrgFull(orgName).getId();
    }

    /**
     * Creates a new Org with the given orgName.
     * The current time is appended to the given orgName.
     * @param orgName Name of org.
     * @return long The Org
     */
    public static Org createNewOrgFull(String orgName) {
        Org org1 = OrgFactory.createOrg();
        org1.setName(orgName + TestUtils.randomString());
        org1 = OrgFactory.save(org1);
        assertTrue(org1.getId() > 0);
        return org1;
    }


    /**
     * Creates a new User and Org with the given userName and orgName.
     * The current time is appended to the given username and orgName.
     * @param userName Name of user.
     * @param orgName Name of org.
     * @return long the user id.
     */
    public static Long createUser(String userName, String orgName) {
        User usr = createUserInternal(userName);
        Long orgId = createOrg(orgName);
        Address addr1 = createTestAddress(usr);
        usr = UserFactory.saveNewUser(usr, addr1, orgId);
        UserFactory.IMPLIEDROLES.forEach(usr::addPermanentRole);

        assertTrue(usr.getId() > 0);
        return usr.getId();
    }

    /**
     * Creates a new User in the specified org
     * @param userName Name of user.
     * @param orgId the org in which to create the user
     * @return long the user id.
     */
    public static User createUser(String userName, Long orgId) {
        return createUserInOrg(userName, orgId, true);
    }

    private static User createUserInOrg(String userName, Long orgId, boolean randomLogin) {
        User usr = createUserInternal(userName, randomLogin);
        Address addr1 = createTestAddress(usr);

        usr = UserFactory.saveNewUser(usr, addr1, orgId);
        UserFactory.IMPLIEDROLES.forEach(usr::addPermanentRole);

        assertTrue(usr.getId() > 0);
        return usr;
    }


    private static User createUserInternal(String userName, boolean randomLogin) {
        UserFactory.getSession();
        User usr = UserFactory.createUser();
        if (randomLogin) {
            usr.setLogin(userName + TestUtils.randomString());
        }
        else {
            usr.setLogin(userName);
        }
        usr.setPassword(TEST_PASSWORD);
        usr.setFirstNames("userName" + TestUtils.randomString());
        usr.setLastName("userName" + TestUtils.randomString());
        String prefix = (String) LocalizationService.getInstance().
        availablePrefixes().toArray()[0];
        usr.setPrefix(prefix);
        usr.setEmail("javaTest@example.com");

        return usr;
    }

    private static User createUserInternal(String userName) {
        return createUserInternal(userName, true);
    }

    /**
     * Creates a new User and Org with the given userName and orgName.
     * The current time is appended to the given username and orgName.
     * @param userName Name of user.
     * @param orgName Name of org.
     * @return User the newly created User.
     */
    public static User findNewUser(String userName, String orgName) {
        return findNewUser(userName, orgName, false);
    }

    /**
     * Creates a new User and Org with the given userName and orgName.
     * The current time is appended to the given username and orgName.
     * @param userName Name of user.
     * @param orgName Name of org.
     * @param orgAdmin if you want the user to have the ORG_ADMIN role
     * @return User the newly created User.
     */
    public static User findNewUser(String userName, String orgName, boolean orgAdmin) {
        Long id = createUser(userName, orgName);
        User usr = UserFactory.lookupById(id);
        if (orgAdmin) {
            usr.getAccessGroups().addAll(List.of(AccessGroupFactory.CHANNEL_ADMIN,
                    AccessGroupFactory.SYSTEM_GROUP_ADMIN, AccessGroupFactory.IMAGE_ADMIN,
                    AccessGroupFactory.ACTIVATION_KEY_ADMIN, AccessGroupFactory.CONFIG_ADMIN));
            usr.addPermanentRole(RoleFactory.ORG_ADMIN);
            UserFactory.save(usr);
        }
        return usr;
    }

    /**
     * Creates a new Org with the given name, then returns the newly
     * created Org.
     * @param orgName Org name
     * @return Org
     */
    public static Org findNewOrg(String orgName) {
        Long id = createOrg(orgName);
        return OrgFactory.lookupById(id);
    }

    /**
     * Create a dummy address to test against
     * @param user the User we want to be the parent of this
     *        Address.
     * @return A dummy address to test against.
     */
    public static Address createTestAddress(User user) {
        user.setAddress1("444 Castro");
        user.setAddress2("#1");
        user.setCity("Mountain View");
        user.setState("CA");
        user.setZip("94043");
        user.setCountry("US");
        user.setPhone("650-555-1212");
        user.setFax("650-555-1212");
        return user.getEnterpriseUser().getAddress();
    }

    /**
     * Create a dummy Address and returns its id.
     * @param user the User we want to be the parent of this
     *        Address.
     * @return the id of the dummy address.
     */
    public static Long createAddress(User user) {
        Address addr = createTestAddress(user);
        assertTrue(addr.getId() > 0);
        return addr.getId();
    }

    /**
     * Check that <code>user</code> is an org_admin, and that
     * there is at least one server visible to her. The second check
     * is necessary because of bz156752
     * @param user the user for which to check
     */
    public static void assertOrgAdmin(User user) {
        boolean act = user.hasRole(RoleFactory.ORG_ADMIN);
        int servers = UserManager.visibleSystems(user).size();
        assertTrue(act, "User must be org_admin");
        assertTrue(servers > 0, "User sees some systems");
    }

    /**
     * Check that <code>user</code> is <em>not</em> an org_admin, and that
     * she can see no servers. The second check
     * is necessary because of bz156752
     * @param user the user for which to check
     */
    public static void assertNotOrgAdmin(User user) {
        boolean act = user.hasRole(RoleFactory.ORG_ADMIN);
        int servers = UserManager.visibleSystems(user).size();
        assertFalse(act, "User must not be org_admin");
        assertEquals(0, servers, "User sees no servers");
    }

    /**
     * Simple method to add a Role to a User.  Will
     * make sure the User's org has the role too
     * @param user to add Role to
     * @param r Role to add.
     */
    public static void addUserRole(User user, Role r) {
        Org o = user.getOrg();
        o.addRole(r);
        user.addPermanentRole(r);
    }

    /**
     * Simple method to add an access group to a User.
     * @param user to add group to
     * @param groupIn the group to add.
     */
    public static void addAccessGroup(User user, AccessGroup groupIn) {
        user.addToGroup(groupIn);
    }

    /**
     * Add provisioning to an org
     * @param orgIn to add to
     */
    public static void addManagement(Org orgIn) {
            ServerGroupTestUtils.createEntitled(orgIn,
                    ServerConstants.getServerGroupTypeEnterpriseEntitled());
    }

    /**
     * Add virtualization to an org
     * @param orgIn to add to
     */
    public static void addVirtualization(Org orgIn) {
        EntitlementServerGroup sg =
            ServerGroupTestUtils.createEntitled(orgIn,
                    ServerConstants.getServerGroupTypeVirtualizationEntitled());
        TestUtils.saveAndFlush(sg);
    }

    /**
     * Create a new user 'testUser' and 'testOrg'
     * @return User created
     */
    public static User findNewUser() {
        return findNewUser("testUser", "testOrg");
    }

    /**
     * Find an Org_ADMIN for the Org passed in.  Create Org_ADMIN if not.
     * @param orgIn to find/create
     * @return User who is Org_ADMIN
     */
    public static User ensureOrgAdminExists(Org orgIn) {
        User retval = UserFactory.findRandomOrgAdmin(orgIn);
        if (retval == null) {
            retval = UserTestUtils.createUser("TestUser", orgIn.getId());
            UserTestUtils.addUserRole(retval, RoleFactory.ORG_ADMIN);
            TestUtils.saveAndFlush(orgIn);
        }
        return retval;
    }
    /**
     * Make sure a user with the passed in *exact* login exists within the org
     * @param login to ensure exists
     * @return User new if not already there
     */
    public static User ensureUserExists(String login) {
        User retval = null;
        try {
            retval = UserFactory.lookupByLogin(login);
        }
        catch (LookupException le) {
            retval = createUserInOrg(login, createOrg("testOrg"), false);
        }
        return retval;
    }

    /**
     * Ensures that an admin user for the Satellite org exists, creating it if
     * necessary.
     */
    public static void ensureSatelliteOrgAdminExists() {
        Org satelliteOrg = OrgFactory.getSatelliteOrg();
        UserTestUtils.ensureOrgAdminExists(satelliteOrg);
    }
}

