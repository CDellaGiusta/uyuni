/*
 * Copyright (c) 2009--2017 Red Hat, Inc.
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

package com.redhat.rhn.manager.action.test;

import static com.redhat.rhn.testing.ImageTestUtils.createActivationKey;
import static com.redhat.rhn.testing.ImageTestUtils.createImageProfile;
import static com.redhat.rhn.testing.ImageTestUtils.createImageStore;
import static java.util.stream.Collectors.toMap;
import static java.util.stream.Collectors.toSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.redhat.rhn.common.conf.Config;
import com.redhat.rhn.common.db.datasource.DataResult;
import com.redhat.rhn.common.hibernate.HibernateFactory;
import com.redhat.rhn.common.hibernate.LookupException;
import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.action.ActionChain;
import com.redhat.rhn.domain.action.ActionChainFactory;
import com.redhat.rhn.domain.action.ActionFactory;
import com.redhat.rhn.domain.action.channel.SubscribeChannelsAction;
import com.redhat.rhn.domain.action.kickstart.KickstartAction;
import com.redhat.rhn.domain.action.kickstart.KickstartActionDetails;
import com.redhat.rhn.domain.action.kickstart.KickstartGuestAction;
import com.redhat.rhn.domain.action.kickstart.KickstartGuestActionDetails;
import com.redhat.rhn.domain.action.rhnpackage.PackageAction;
import com.redhat.rhn.domain.action.salt.build.ImageBuildAction;
import com.redhat.rhn.domain.action.script.ScriptActionDetails;
import com.redhat.rhn.domain.action.script.ScriptRunAction;
import com.redhat.rhn.domain.action.server.ServerAction;
import com.redhat.rhn.domain.action.server.test.ServerActionTest;
import com.redhat.rhn.domain.action.test.ActionFactoryTest;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.test.ChannelFactoryTest;
import com.redhat.rhn.domain.errata.Errata;
import com.redhat.rhn.domain.errata.test.ErrataFactoryTest;
import com.redhat.rhn.domain.image.ImageInfoFactory;
import com.redhat.rhn.domain.image.ImageProfile;
import com.redhat.rhn.domain.image.ImageStore;
import com.redhat.rhn.domain.kickstart.KickstartData;
import com.redhat.rhn.domain.kickstart.KickstartSession;
import com.redhat.rhn.domain.kickstart.KickstartSessionHistory;
import com.redhat.rhn.domain.kickstart.test.KickstartDataTest;
import com.redhat.rhn.domain.kickstart.test.KickstartSessionTest;
import com.redhat.rhn.domain.rhnpackage.Package;
import com.redhat.rhn.domain.rhnpackage.test.PackageTest;
import com.redhat.rhn.domain.rhnset.RhnSet;
import com.redhat.rhn.domain.rhnset.SetCleanup;
import com.redhat.rhn.domain.role.RoleFactory;
import com.redhat.rhn.domain.server.MinionServer;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.server.ServerConstants;
import com.redhat.rhn.domain.server.ServerFactory;
import com.redhat.rhn.domain.server.ServerGroupFactory;
import com.redhat.rhn.domain.server.test.MinionServerFactoryTest;
import com.redhat.rhn.domain.server.test.ServerFactoryTest;
import com.redhat.rhn.domain.token.ActivationKey;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.domain.user.UserFactory;
import com.redhat.rhn.frontend.dto.ActionedSystem;
import com.redhat.rhn.frontend.dto.PackageListItem;
import com.redhat.rhn.frontend.dto.PackageMetadata;
import com.redhat.rhn.frontend.dto.ScheduledAction;
import com.redhat.rhn.frontend.listview.PageControl;
import com.redhat.rhn.manager.action.ActionChainManager;
import com.redhat.rhn.manager.action.ActionIsChildException;
import com.redhat.rhn.manager.action.ActionManager;
import com.redhat.rhn.manager.entitlement.EntitlementManager;
import com.redhat.rhn.manager.kickstart.ProvisionVirtualInstanceCommand;
import com.redhat.rhn.manager.profile.ProfileManager;
import com.redhat.rhn.manager.profile.test.ProfileManagerTest;
import com.redhat.rhn.manager.rhnset.RhnSetDecl;
import com.redhat.rhn.manager.rhnset.RhnSetManager;
import com.redhat.rhn.manager.system.SystemManager;
import com.redhat.rhn.manager.system.entitling.SystemEntitlementManager;
import com.redhat.rhn.manager.system.entitling.SystemEntitler;
import com.redhat.rhn.manager.system.entitling.SystemUnentitler;
import com.redhat.rhn.manager.system.test.SystemManagerTest;
import com.redhat.rhn.taskomatic.TaskomaticApi;
import com.redhat.rhn.taskomatic.TaskomaticApiException;
import com.redhat.rhn.testing.JMockBaseTestCaseWithUser;
import com.redhat.rhn.testing.ServerTestUtils;
import com.redhat.rhn.testing.TestUtils;
import com.redhat.rhn.testing.UserTestUtils;

import com.suse.manager.webui.services.iface.SaltApi;
import com.suse.manager.webui.services.iface.SystemQuery;
import com.suse.manager.webui.services.test.TestSaltApi;
import com.suse.manager.webui.services.test.TestSystemQuery;
import com.suse.salt.netapi.calls.modules.Schedule;
import com.suse.salt.netapi.results.Result;
import com.suse.salt.netapi.utils.Xor;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.query.Query;
import org.jmock.Expectations;
import org.jmock.imposters.ByteBuddyClassImposteriser;
import org.jmock.lib.concurrent.Synchroniser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Tests for {@link ActionManager}.
 */
public class ActionManagerTest extends JMockBaseTestCaseWithUser {
    private static Logger log = LogManager.getLogger(ActionManagerTest.class);
    private static TaskomaticApi taskomaticApi;
    private final SystemQuery systemQuery = new TestSystemQuery();
    private final SaltApi saltApi = new TestSaltApi() {
        @Override
        public void deleteKey(String minionId) {
            // do not call API in a test
        }
    };
    private final SystemEntitlementManager systemEntitlementManager = new SystemEntitlementManager(
            new SystemUnentitler(saltApi), new SystemEntitler(saltApi)
    );
    private final SystemManager systemManager =
            new SystemManager(ServerFactory.SINGLETON, new ServerGroupFactory(), saltApi);

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        context.setThreadingPolicy(new Synchroniser());
        setImposteriser(ByteBuddyClassImposteriser.INSTANCE);
        Config.get().setString("server.secret_key",
                DigestUtils.sha256Hex(TestUtils.randomString()));
    }


    @Test
    public void testGetSystemGroups() throws Exception {
        ActionFactoryTest.createAction(user, ActionFactory.TYPE_REBOOT);
        ActionFactoryTest.createAction(user, ActionFactory.TYPE_REBOOT);

        PageControl pc = new PageControl();
        pc.setIndexData(false);
        pc.setFilterColumn("earliest");
        pc.setStart(1);
        DataResult<ScheduledAction> dr = ActionManager.pendingActions(user, pc);
        assertNotNull(dr);
        assertFalse(dr.isEmpty());
    }

    @Test
    public void testLookupAction() throws Exception {
        Action a1 = ActionFactoryTest.createAction(user, ActionFactory.TYPE_REBOOT);
        Long actionId = a1.getId();

        //Users must have access to a server for the action to lookup the action
        Server s = ServerFactoryTest.createTestServer(user, true);
        a1.addServerAction(ServerActionTest.createServerAction(s, a1));
        ActionManager.storeAction(a1);

        Action a2 = ActionManager.lookupAction(user, actionId);
        assertNotNull(a2);
    }

    @Test
    public void testActionsArchivedOnSystemDeleteUser() throws Exception {
        Server server = ServerTestUtils.createTestSystem(user);

        Action action = ActionFactoryTest.createAction(user, ActionFactory.TYPE_ERRATA);
        ServerAction serverAction = ServerActionTest.createServerAction(server, action);
        serverAction.setStatusCompleted();

        action.addServerAction(serverAction);
        ActionManager.storeAction(action);

        Action result = ActionManager.lookupAction(user, action.getId());
        assertNotNull(result);

        systemManager.deleteServer(user, server.getId());

        try {
            // Regular users cannot see orphan actions
            ActionManager.lookupAction(user, action.getId());
            fail("Must throw LookupException.");
        }
        catch (LookupException ignored) {
            //should be here
        }
    }

    @Test
    public void testActionsArchivedOnSystemDeleteAdmin() throws Exception {
        user.addPermanentRole(RoleFactory.ORG_ADMIN);
        Server server = ServerTestUtils.createTestSystem(user);
        Action action = ActionFactoryTest.createAction(user, ActionFactory.TYPE_ERRATA);
        ServerAction serverAction = ServerActionTest.createServerAction(server, action);
        serverAction.setStatusCompleted();

        action.addServerAction(serverAction);
        ActionManager.storeAction(action);

        Action result = ActionManager.lookupAction(user, action.getId());
        assertNotNull(result);

        systemManager.deleteServer(user, server.getId());
        // Admins should see orphan actions
        result = ActionManager.lookupAction(user, action.getId());
        assertNotNull(result);
        assertEquals(1, (long) result.getArchived());
        assertServerActionCount(action, 0);
    }

    @Test
    public void testFailedActions() throws Exception {
        user.addPermanentRole(RoleFactory.ORG_ADMIN);
        Action parent = ActionFactoryTest.createAction(user, ActionFactory.TYPE_ERRATA);
        ServerAction child = ServerActionTest.createServerAction(ServerFactoryTest
                .createTestServer(user), parent);

        child.setStatusFailed();

        parent.addServerAction(child);
        ActionFactory.save(parent);
        UserFactory.save(user);

        DataResult<ScheduledAction> dr = ActionManager.failedActions(user, null);
        assertNotEmpty(dr);
    }

    @Test
    public void testPendingActions() throws Exception {
        user.addPermanentRole(RoleFactory.ORG_ADMIN);
        Action parent = ActionFactoryTest.createAction(user, ActionFactory.TYPE_ERRATA);
        ServerAction child = ServerActionTest.createServerAction(ServerFactoryTest
                .createTestServer(user), parent);

        child.setStatusQueued();

        parent.addServerAction(child);
        ActionFactory.save(parent);
        UserFactory.save(user);

        DataResult<ScheduledAction> dr = ActionManager.pendingActions(user, null);

        Long actionid = parent.getId();
        TestUtils.arraySearch(dr.toArray(), "getId", actionid);
        assertNotEmpty(dr);
    }

    private Action createActionWithServerActions(User user, int numServerActions)
        throws Exception {
        Action parent = ActionFactoryTest.createAction(user, ActionFactory.TYPE_ERRATA);
        Channel baseChannel = ChannelFactoryTest.createTestChannel(user);
        baseChannel.setParentChannel(null);
        for (int i = 0; i < numServerActions; i++) {
            Server server = ServerFactoryTest.createTestServer(user, true);
            server.addChannel(baseChannel);
            TestUtils.saveAndFlush(server);

            ServerAction child = ServerActionTest.createServerAction(server, parent);
            child.setStatusQueued();
            TestUtils.saveAndFlush(child);

            parent.addServerAction(child);
        }
        ActionFactory.save(parent);
        return parent;
    }

    private Action createActionWithMinionServerActions(User user, Consumer<ServerAction> statusSetter,
                                                       int numServerActions)
            throws Exception {
        return createActionWithMinionServerActions(user, statusSetter, numServerActions,
                i -> {
                    try {
                        return MinionServerFactoryTest.createTestMinionServer(user);
                    }
                    catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    private Action createActionWithMinionServerActions(User user, Consumer<ServerAction> statusSetter,
                                                       int numServerActions,
                                                       Function<Integer, ? extends Server> serverFactory)
            throws Exception {
        Action parent = ActionFactoryTest.createAction(user, ActionFactory.TYPE_ERRATA);
        Channel baseChannel = ChannelFactoryTest.createTestChannel(user);
        baseChannel.setParentChannel(null);
        for (int i = 0; i < numServerActions; i++) {
            Server server = serverFactory.apply(i);
            server.addChannel(baseChannel);
            TestUtils.saveAndFlush(server);

            ServerAction child = ServerActionTest.createServerAction(server, parent);
            statusSetter.accept(child);
            TestUtils.saveAndFlush(child);

            parent.addServerAction(child);
        }
        ActionFactory.save(parent);
        return parent;
    }

    private List<Action> createActionList(User user, Action... actions) {
        List<Action> returnList = new LinkedList<>();

        for (Action actionIn : actions) {
            returnList.add(actionIn);
        }

        return returnList;
    }

    private List<ServerAction> getServerActions(Action parentAction) {
        Session session = HibernateFactory.getSession();
        Query query = session.createQuery("from ServerAction sa where " +
            "sa.parentAction = :parent_action");
        query.setParameter("parent_action", parentAction);
        return query.list();
    }

    private void assertServerActionCount(Action parentAction, int expected) {
        assertEquals(expected, getServerActions(parentAction).size());
    }

    private void assertServerActionStatus(Action parentAction, Server server, Predicate<ServerAction> statusPredicate) {
        boolean found = false;
        for (ServerAction sa : getServerActions(parentAction)) {
            if (server.equals(sa.getServer())) {
                assertTrue(statusPredicate.test(sa));
                found = true;
            }
        }
        if (!found) {
            fail("Server not found: " + server.getName());
        }
    }

    public void assertServerActionCount(User user, int expected) {
        Session session = HibernateFactory.getSession();
        Query query = session.createQuery("from ServerAction sa where " +
            "sa.parentAction.schedulerUser = :user");
        query.setParameter("user", user);
        List results = query.list();
        int initialSize = results.size();
        assertEquals(expected, initialSize);
    }

    public void assertActionsForUser(User user, int expected) {
        Session session = HibernateFactory.getSession();
        Query query = session.createQuery("from Action a where a.schedulerUser = :user");
        query.setParameter("user", user);
        List results = query.list();
        int initialSize = results.size();
        assertEquals(expected, initialSize);
    }

    @Test
    public void testSimpleCancelActions() throws Exception {
        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionManager.setTaskomaticApi(taskomaticMock);

        Action parent = createActionWithServerActions(user, 1);
        List<Action> actionList = createActionList(user, parent);

        context().checking(new Expectations() { {
            allowing(taskomaticMock).deleteScheduledActions(with(any(Map.class)));
        } });

        assertServerActionCount(parent, 1);
        assertActionsForUser(user, 1);
        ActionManager.cancelActions(user, actionList);
        assertServerActionCount(parent, 0);
        assertActionsForUser(user, 1); // shouldn't have been deleted
    }

    @Test
    public void testSimpleCancelMinionActions() throws Exception {
        Action parent = createActionWithMinionServerActions(user, ServerAction::setStatusQueued, 3);
        List actionList = createActionList(user, new Action [] {parent});

        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionManager.setTaskomaticApi(taskomaticMock);

        ServerAction[] sa = parent.getServerActions().toArray(new ServerAction[3]);
        Map<String, Result<Schedule.Result>> result = new HashMap<>();
        result.put(sa[0].getServer().asMinionServer().get().getMinionId(),
                new Result<>(Xor.right(new Schedule.Result(null, true))));
        result.put(sa[1].getServer().asMinionServer().get().getMinionId(),
                new Result<>(Xor.right(new Schedule.Result("Job 123 does not exist.", false))));

        Set<Server> servers = new HashSet<>();
        servers.add(sa[0].getServer());
        servers.add(sa[1].getServer());
        servers.add(sa[2].getServer());

        Map<Action, Set<Server>> actionMap = Collections.singletonMap(parent, servers);

        context().checking(new Expectations() { {
            allowing(taskomaticMock).deleteScheduledActions(with(equal(actionMap)));
        } });

        assertServerActionCount(parent, 3);
        assertActionsForUser(user, 1);

        ActionManager.cancelActions(user, actionList);

        assertServerActionCount(parent, 0);
        assertActionsForUser(user, 1); // shouldn't have been deleted
        context().assertIsSatisfied();
    }

    /**
     * An action that is PICKEDUP should be set to FAILED when canceled, but COMPLETED or FAILED server actions should
     * not be affected of a cancellation (bsc#1098993).
     */
    @Test
    public void testCancelMinionActionsMixedStatus() throws Exception {
        Action action = createActionWithMinionServerActions(user, ServerAction::setStatusPickedUp, 3);

        // Set first server action to COMPLETED
        Iterator<ServerAction> iterator = action.getServerActions().iterator();
        ServerAction completed = iterator.next();
        Server serverCompleted = completed.getServer();
        completed.setStatusCompleted();

        // Set second server action to FAILED
        ServerAction failed = iterator.next();
        Server serverFailed = failed.getServer();
        failed.setStatusFailed();

        // Third server action stays in PICKEDUP
        ServerAction pickedUp = iterator.next();
        Server serverPickedUp = pickedUp.getServer();

        List<Action> actionList = createActionList(user, action);
        ActionManager.cancelActions(user, actionList);

        assertServerActionCount(action, 3);
        assertServerActionStatus(action, serverCompleted, ServerAction::isStatusCompleted);
        assertServerActionStatus(action, serverFailed, ServerAction::isStatusFailed);
        assertServerActionStatus(action, serverPickedUp, ServerAction::isStatusFailed);
    }

    @Test
    public void testSimpleCancelMixedActions() throws Exception {
        Action parent = createActionWithMinionServerActions(user, ServerAction::setStatusQueued, 4,
                i -> {
                    try {
                        if (i < 3) {
                            return MinionServerFactoryTest.createTestMinionServer(user);
                        }
                        else {
                            return ServerFactoryTest.createTestServer(user, true,
                                    ServerConstants.getServerGroupTypeEnterpriseEntitled());
                        }
                    }
                    catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
        List actionList = createActionList(user, new Action [] {parent});

        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionManager.setTaskomaticApi(taskomaticMock);

        List<ServerAction> sa = parent.getServerActions().stream()
                .filter(s -> s.getServer().asMinionServer().isPresent())
                .toList();
        Map<String, Result<Schedule.Result>> result = new HashMap<>();
        result.put(sa.get(0).getServer().asMinionServer().get().getMinionId(),
                new Result<>(Xor.right(new Schedule.Result(null, true))));
        result.put(sa.get(1).getServer().asMinionServer().get().getMinionId(),
                new Result<>(Xor.right(new Schedule.Result("Job 123 does not exist.", false))));

        Set<Server> servers = new HashSet<>();
        servers.add(sa.get(0).getServer());
        servers.add(sa.get(1).getServer());
        servers.add(sa.get(2).getServer());

        Map<Action, Set<Server>> actionMap = Collections.singletonMap(parent, servers);

        context().checking(new Expectations() { {
            allowing(taskomaticMock).deleteScheduledActions(with(equal(actionMap)));
        } });
        parent.getServerActions().stream()
                .filter(s -> !s.getServer().asMinionServer().isPresent())
                .findFirst();

        assertServerActionCount(parent, 4);
        assertActionsForUser(user, 1);

        ActionManager.cancelActions(user, actionList);

        assertServerActionCount(parent, 0);
        assertActionsForUser(user, 1); // shouldn't have been deleted
        context().assertIsSatisfied();
    }

    @Test
    public void testCancelActionWithChildren() throws Exception {
        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionManager.setTaskomaticApi(taskomaticMock);
        Action parent = createActionWithServerActions(user, 1);
        Action child = createActionWithServerActions(user, 1);
        child.setPrerequisite(parent);
        List<Action> actionList = createActionList(user, parent);

        assertServerActionCount(parent, 1);
        assertActionsForUser(user, 2);

        context().checking(new Expectations() { {
            allowing(taskomaticMock).deleteScheduledActions(with(any(Map.class)));
        } });

        ActionManager.cancelActions(user, actionList);
        assertServerActionCount(parent, 0);
        assertActionsForUser(user, 2); // shouldn't have been deleted
    }

    @Test
    public void testCancelActionWithMultipleServerActions() throws Exception {
        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionManager.setTaskomaticApi(taskomaticMock);
        context().checking(new Expectations() { {
            allowing(taskomaticMock).deleteScheduledActions(with(any(Map.class)));
        } });

        Action parent = createActionWithServerActions(user, 2);
        List<Action> actionList = Collections.singletonList(parent);

        assertServerActionCount(parent, 2);
        assertActionsForUser(user, 1);
        ActionManager.cancelActions(user, actionList);
        assertServerActionCount(parent, 0);
        assertActionsForUser(user, 1); // shouldn't have been deleted
    }

    @Test
    public void testCancelActionForSubsetOfServerWithMultipleServerActions() throws Exception {
        Action parent = createActionWithServerActions(user, 2);
        List<Action> actionList = Collections.singletonList(parent);
        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionManager.setTaskomaticApi(taskomaticMock);

        List<Server> servers = actionList.stream()
                .flatMap(a -> a.getServerActions().stream())
                .map(ServerAction::getServer)
                .collect(Collectors.toList());

        servers.remove(0);
        Collection<Long> activeServers = servers.stream().map(Server::getId).collect(Collectors.toList());

        Map<Action, Set<Server>> actionMap = actionList.stream()
                .map(a -> new ImmutablePair<>(
                                a,
                                a.getServerActions().stream()
                                        .map(ServerAction::getServer)
                                        .collect(toSet())
                        )
                )
                .collect(toMap(
                        Pair::getLeft,
                        Pair::getRight
                ));

        context().checking(new Expectations() { {
            never(taskomaticMock).deleteScheduledActions(with(same(actionMap)));
        } });

        assertServerActionCount(parent, 2);
        assertActionsForUser(user, 1);
        ActionManager.cancelActions(user, actionList, activeServers);
        assertServerActionCount(parent, 1);
        assertActionsForUser(user, 1); // shouldn't have been deleted
        // check that action was indeed not canceled on taskomatic side
        context().assertIsSatisfied();
    }

    @Test
    public void testCancelActionWithFailedPrerequisite() throws TaskomaticApiException {
        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionManager.setTaskomaticApi(taskomaticMock);

        Server first = ServerFactoryTest.createTestServer(user, true);
        Server second = ServerFactoryTest.createTestServer(user, true);
        List<Server> servers = List.of(first, second);

        Action parent = ActionFactoryTest.createEmptyAction(user, ActionFactory.TYPE_SCRIPT_RUN);
        ActionFactory.save(parent);

        servers.forEach(server -> {
            ServerAction serverAction = ActionFactoryTest.createServerAction(server, parent);
            if (first.equals(server)) {
                serverAction.setStatusFailed();
            }
            else {
                serverAction.setStatusQueued();
            }
            parent.addServerAction(serverAction);
            ActionFactory.save(serverAction);
        });

        Action child = ActionFactoryTest.createEmptyAction(user, ActionFactory.TYPE_ERRATA);
        child.setPrerequisite(parent);
        ActionFactory.save(child);

        servers.forEach(server -> {
            ServerAction serverAction = ActionFactoryTest.createServerAction(server, child);
            serverAction.setStatusQueued();
            child.addServerAction(serverAction);
            ActionFactory.save(serverAction);
        });

        // Should not cancel, there are pending prerequisites
        List<Action> actionsToCancel = List.of(TestUtils.reload(child));
        Assertions.assertThrows(ActionIsChildException.class,
            () -> ActionManager.cancelActions(user, actionsToCancel)
        );

        context().checking(new Expectations() { {
            allowing(taskomaticMock).deleteScheduledActions(with(Map.of(actionsToCancel.get(0), Set.of(first))));
        } });

        // Should cancel, first server has a failed prerequisite
        Assertions.assertDoesNotThrow(
            () -> ActionManager.cancelActions(user, actionsToCancel, List.of(first.getId()))
        );

        // Should not cancel, second server as a valid pending prerequisite
        Assertions.assertThrows(ActionIsChildException.class,
            () -> ActionManager.cancelActions(user, actionsToCancel, List.of(second.getId()))
        );
    }

    @Test
    public void testCancelActionWithParentFails() throws Exception {
        Action parent = createActionWithServerActions(user, 1);
        Action child = createActionWithServerActions(user, 1);
        child.setPrerequisite(parent);
        List actionList = createActionList(user, new Action [] {child});

        try {
            ActionManager.cancelActions(user, actionList);
            fail("Exception not thrown when deleting action with a prerequisite.");
        }
        catch (ActionIsChildException e) {
            // expected
        }
    }

    @Test
    public void testComplexHierarchy() throws Exception {
        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionManager.setTaskomaticApi(taskomaticMock);

        Action parent1 = createActionWithServerActions(user, 3);
        for (int i = 0; i < 9; i++) {
            Action child = createActionWithServerActions(user, 2);
            child.setPrerequisite(parent1);
        }
        Action parent2 = createActionWithServerActions(user, 3);
        for (int i = 0; i < 9; i++) {
            Action child = createActionWithServerActions(user, 2);
            child.setPrerequisite(parent2);
        }
        assertServerActionCount(user, 42);

        List<Action> actionList = createActionList(user, parent1, parent2);

        assertServerActionCount(parent1, 3);
        assertActionsForUser(user, 20);

        context().checking(new Expectations() { {
            allowing(taskomaticMock).deleteScheduledActions(with(any(Map.class)));
        } });
        ActionManager.cancelActions(user, actionList);
        assertServerActionCount(parent1, 0);
        assertActionsForUser(user, 20); // shouldn't have been deleted
        assertServerActionCount(user, 0);

    }

    @Test
    public void testCancelKickstartAction() throws Exception {
        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionManager.setTaskomaticApi(taskomaticMock);
        Session session = HibernateFactory.getSession();
        Action parentAction = createActionWithServerActions(user, 1);
        Server server = parentAction.getServerActions().iterator().next()
            .getServer();
        ActionFactory.save(parentAction);

        KickstartDataTest.setupTestConfiguration(user);
        KickstartData ksData = KickstartDataTest.createKickstartWithOptions(user.getOrg());
        KickstartSession ksSession = KickstartSessionTest.createKickstartSession(server,
                ksData, user, parentAction);
        TestUtils.saveAndFlush(ksSession);
        ksSession = reload(ksSession);

        List<Action> actionList = createActionList(user, parentAction);

        Query<KickstartSession> kickstartSessions = session.createQuery(
                "from KickstartSession ks where ks.action = :action", KickstartSession.class);
        kickstartSessions.setParameter("action", parentAction);
        List<KickstartSession> results = kickstartSessions.list();
        assertEquals(1, results.size());

        assertEquals(1, ksSession.getHistory().size());
        KickstartSessionHistory history = ksSession.getHistory().iterator().next();
        assertEquals("created", history.getState().getLabel());

        context().checking(new Expectations() { {
            allowing(taskomaticMock).deleteScheduledActions(with(any(Map.class)));
        } });

        ActionManager.cancelActions(user, actionList);

        // New history entry should have been created:
        assertEquals(2, ksSession.getHistory().size());

        // Test that the kickstart wasn't deleted but rather marked as failed:
        assertEquals("failed", ksSession.getState().getLabel());
    }

    @Test
    public void testCompletedActions() throws Exception {
        user.addPermanentRole(RoleFactory.ORG_ADMIN);
        Action parent = ActionFactoryTest.createAction(user, ActionFactory.TYPE_ERRATA);
        ServerAction child = ServerActionTest.createServerAction(ServerFactoryTest
                .createTestServer(user), parent);

        child.setStatusCompleted();

        parent.addServerAction(child);
        ActionFactory.save(parent);
        UserFactory.save(user);

        DataResult<ScheduledAction> dr = ActionManager.completedActions(user, null);
        assertNotEmpty(dr);
    }

    @Test
    public void testRecentlyScheduledActions() throws Exception {
        user.addPermanentRole(RoleFactory.ORG_ADMIN);
        Action parent = ActionFactoryTest.createAction(user, ActionFactory.TYPE_ERRATA);
        ServerAction child = ServerActionTest.createServerAction(ServerFactoryTest
                .createTestServer(user), parent);

        child.setStatusCompleted();
        child.setCreated(new Date(System.currentTimeMillis()));

        parent.addServerAction(child);
        ActionFactory.save(parent);
        UserFactory.save(user);

        DataResult dr = ActionManager.recentlyScheduledActions(user, null, 30);
        assertNotEmpty(dr);
    }

    @Test
    public void testLookupFailLookupAction() {
        try {
            ActionManager.lookupAction(user, -1L);
            fail("Expected to fail");
        }
        catch (LookupException le) {
            assertTrue(true);
        }
    }

    @Test
    public void testRescheduleAction() throws Exception {
        Action a1 = ActionFactoryTest.createAction(user, ActionFactory.TYPE_REBOOT);
        ServerAction sa = (ServerAction) a1.getServerActions().toArray()[0];

        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionManager.setTaskomaticApi(taskomaticMock);

        context().checking(new Expectations() { {
            allowing(taskomaticMock).scheduleActionExecution(with(any(Action.class)));
        } });

        sa.setStatusFailed();
        sa.setRemainingTries(0L);
        ActionFactory.save(a1);

        ActionManager.rescheduleAction(a1);
        sa = (ServerAction) ActionFactory.reload(sa);
        assertTrue(sa.isStatusQueued());
        assertTrue(sa.getRemainingTries() > 0);
    }

    @Test
    public void testInProgressSystems() throws Exception {
        Action a1 = ActionFactoryTest.createAction(user, ActionFactory.TYPE_REBOOT);
        ServerAction sa = (ServerAction) a1.getServerActions().toArray()[0];

        sa.setStatusQueued();
        ActionFactory.save(a1);
        DataResult<ActionedSystem> dr = ActionManager.inProgressSystems(user, a1, null);
        assertFalse(dr.isEmpty());
        assertNotNull(dr.get(0));
        ActionedSystem as = dr.get(0);
        as.setSecurityErrata(1L);
        assertNotNull(as.getSecurityErrata());
    }

    @Test
    public void testFailedSystems() throws Exception {
        Action a1 = ActionFactoryTest.createAction(user, ActionFactory.TYPE_REBOOT);
        ServerAction sa = (ServerAction) a1.getServerActions().toArray()[0];

        sa.setStatusFailed();
        ActionFactory.save(a1);

        assertFalse(ActionManager.failedSystems(user, a1, null).isEmpty());
    }

    @Test
    public void testCreateErrataAction() throws Exception {
        Errata errata = ErrataFactoryTest.createTestErrata(user.getOrg().getId());

        Action a = ActionManager.createErrataAction(user.getOrg(), errata);
        assertNotNull(a);
        assertNull(a.getSchedulerUser());
        assertEquals(user.getOrg(), a.getOrg());
        assertEquals(a.getActionType(), ActionFactory.TYPE_ERRATA);

        a = ActionManager.createErrataAction(user, errata);
        assertNotNull(a);
        assertEquals(user, a.getSchedulerUser());
        assertEquals(user.getOrg(), a.getOrg());
        assertEquals(a.getActionType(), ActionFactory.TYPE_ERRATA);
    }

    @Test
    public void testAddServerToAction() throws Exception {
        User usr = UserTestUtils.createUser("testUser",
                UserTestUtils.createOrg("testOrg" + this.getClass().getSimpleName()));
        Server s = ServerFactoryTest.createTestServer(usr);
        Action a = ActionFactoryTest.createAction(usr, ActionFactory.TYPE_ERRATA);
        ActionManager.addServerToAction(s.getId(), a);

        assertNotNull(a.getServerActions());
        assertEquals(a.getServerActions().size(), 1);
        Object[] array = a.getServerActions().toArray();
        ServerAction sa = (ServerAction)array[0];
        assertTrue(sa.isStatusQueued());
        assertEquals(sa.getServer(), s);
    }

    @Test
    public void testSchedulePackageRemoval() throws Exception {
        ActionManager.setTaskomaticApi(getTaskomaticApi());
        Server srvr = ServerFactoryTest.createTestServer(user, true);
        RhnSet set = RhnSetManager.createSet(user.getId(), "removable_package_list",
                SetCleanup.NOOP);
        assertNotNull(srvr);
        assertNotNull(set);

        Package pkg = PackageTest.createTestPackage(user.getOrg());

        set.addElement(pkg.getPackageName().getId(), pkg.getPackageEvr().getId(),
                pkg.getPackageArch().getId());
        RhnSetManager.store(set);

        PackageAction pa = ActionManager.schedulePackageRemoval(user, srvr,
            set, new Date());
        assertNotNull(pa);
        assertNotNull(pa.getId());
        PackageAction pa1 = (PackageAction) ActionManager.lookupAction(user, pa.getId());
        assertNotNull(pa1);
        assertEquals(pa, pa1);
    }

    @Test
    public void testSchedulePackageVerify() throws Exception {
        ActionManager.setTaskomaticApi(getTaskomaticApi());
        Server srvr = ServerFactoryTest.createTestServer(user, true);
        RhnSet set = RhnSetManager.createSet(user.getId(), "verify_package_list",
                SetCleanup.NOOP);
        assertNotNull(srvr);
        assertNotNull(set);

        Package pkg = PackageTest.createTestPackage(user.getOrg());

        set.addElement(pkg.getPackageName().getId(), pkg.getPackageEvr().getId(),
                pkg.getPackageArch().getId());
        RhnSetManager.store(set);

        PackageAction pa = ActionManager.schedulePackageVerify(user, srvr, set, new Date());
        assertNotNull(pa);
        assertNotNull(pa.getId());
        PackageAction pa1 = (PackageAction) ActionManager.lookupAction(user, pa.getId());
        assertNotNull(pa1);
        assertEquals(pa, pa1);
    }

    @Test
    public void testScheduleScriptRun() throws Exception {
        ActionManager.setTaskomaticApi(getTaskomaticApi());
        Server srvr = ServerFactoryTest.createTestServer(user, true);
        SystemManagerTest.giveCapability(srvr.getId(), "script.run", 1L);
        assertNotNull(srvr);

        List<Long> serverIds = new ArrayList<>();
        serverIds.add(srvr.getId());

        ScriptActionDetails sad = ActionFactory.createScriptActionDetails(
                "root", "root", 10L, "#!/bin/csh\necho hello");
        assertNotNull(sad);
        ScriptRunAction sra = ActionManager.scheduleScriptRun(
                user, serverIds, "Run script test", sad, new Date());
        assertNotNull(sra);
        assertNotNull(sra.getId());
        ScriptRunAction pa1 = (ScriptRunAction)
                ActionManager.lookupAction(user, sra.getId());
        assertNotNull(pa1);
        assertEquals(sra, pa1);
        ScriptActionDetails sad1 = pa1.getScriptActionDetails();
        assertNotNull(sad1);
        assertEquals(sad, sad1);
    }

    @Test
    public void testScheduleKickstart() throws Exception {
        Server srvr = ServerFactoryTest.createTestServer(user, true);
        assertNotNull(srvr);
        KickstartDataTest.setupTestConfiguration(user);
        KickstartData testKickstartData
            = KickstartDataTest.createKickstartWithChannel(user.getOrg());

        KickstartAction ka
            = ActionManager.scheduleKickstartAction(testKickstartData,
                                                    user,
                                                    srvr,
                                                    new Date(System.currentTimeMillis()),
                                                    "",
                                                    "localhost");
        assertNotNull(ka);
        TestUtils.saveAndFlush(ka);
        assertNotNull(ka.getId());
        KickstartActionDetails kad = ka.getKickstartActionDetails();
        KickstartAction ka2 = (KickstartAction)
            ActionManager.lookupAction(user, ka.getId());
        assertNotNull(ka2);
        assertEquals(ka, ka2);
        KickstartActionDetails kad2 = ka2.getKickstartActionDetails();
        assertNotNull(kad);
        assertEquals(kad, kad2);
    }

    @Test
    public void testScheduleGuestKickstart() throws Exception {
        user.addPermanentRole(RoleFactory.ORG_ADMIN);
        Server srvr = ServerFactoryTest.createTestServer(user, true);
        assertNotNull(srvr);
        KickstartDataTest.setupTestConfiguration(user);
        KickstartData testKickstartData
            = KickstartDataTest.createKickstartWithChannel(user.getOrg());

        KickstartSession ksSession =
            KickstartSessionTest.createKickstartSession(srvr,
                                                        testKickstartData,
                                                        user);
        TestUtils.saveAndFlush(ksSession);

        String kickstartHost = "localhost.localdomain";
        ProvisionVirtualInstanceCommand command =
            new ProvisionVirtualInstanceCommand(srvr.getId(),
                                                testKickstartData.getId(),
                                                user,
                                                new Date(System.currentTimeMillis()),
                                                kickstartHost);

        command.setGuestName("testGuest1");
        command.setMemoryAllocation(256L);
        command.setLocalStorageSize(2L);
        command.setVirtualCpus(2L);
        command.setKickstartSession(ksSession);
        KickstartGuestAction ka =
            ActionManager.scheduleKickstartGuestAction(command, ksSession.getId());
        assertEquals(kickstartHost,
                ka.getKickstartGuestActionDetails().getKickstartHost());

        assertNotNull(ka);
        TestUtils.saveAndFlush(ka);
        assertNotNull(ka.getId());
        KickstartGuestActionDetails kad =
            ka.getKickstartGuestActionDetails();
        KickstartGuestAction ka2 = (KickstartGuestAction)
            ActionManager.lookupAction(user, ka.getId());
        assertNotNull(ka2);
        assertNotNull(kad.getCobblerSystemName());
        assertEquals(ka, ka2);
        KickstartGuestActionDetails kad2 =
            ka2.getKickstartGuestActionDetails();
        assertNotNull(kad);
        assertEquals(kad, kad2);

        assertEquals("256", kad.getMemMb().toString());
        assertEquals("2", kad.getVcpus().toString());
        assertEquals("testGuest1", kad.getGuestName());
        assertEquals("2", kad.getDiskGb().toString());
    }

    @SuppressWarnings("rawtypes")
    @Test
    public void testSchedulePackageDelta() throws Exception {
        ActionManager.setTaskomaticApi(getTaskomaticApi());

        Server srvr = ServerFactoryTest.createTestServer(user, true);

        List<PackageListItem> profileList = new ArrayList<>();
        profileList.add(ProfileManagerTest.
                createPackageListItem("kernel-2.4.23-EL-mmccune", 500341));
        profileList.add(ProfileManagerTest.
                createPackageListItem("kernel-2.4.24-EL-mmccune", 500341));
        profileList.add(ProfileManagerTest.
                createPackageListItem("kernel-2.4.25-EL-mmccune", 500341));

        List<PackageListItem> systemList = new ArrayList<>();
        systemList.add(ProfileManagerTest.
                createPackageListItem("kernel-2.4.23-EL-mmccune", 500341));


        RhnSetDecl.PACKAGES_FOR_SYSTEM_SYNC.get(user);


        List<PackageMetadata> pkgs = ProfileManager.comparePackageLists(new DataResult<>(profileList),
                new DataResult<>(systemList), "foo");

        PackageAction pa = ActionManager.schedulePackageRunTransaction(user, srvr, pkgs, new Date());
        assertInstanceOf(PackageAction.class, pa);

        Map<String, Object> params = new HashMap<>();
        params.put("action_id", pa.getId());
        DataResult dr = TestUtils.runTestQuery("package_install_list", params);
        assertEquals(2, dr.size());
    }

    @Test
    public void testScheduleSubscribeChannels() throws Exception {
        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionChainManager.setTaskomaticApi(taskomaticMock);
        context().checking(new Expectations() { {
            allowing(taskomaticMock).scheduleSubscribeChannels(with(any(User.class)),
                    with(any(SubscribeChannelsAction.class)));
        } });

        MinionServer srvr = MinionServerFactoryTest.createTestMinionServer(user);
        Channel base = ChannelFactoryTest.createBaseChannel(user);
        Channel ch1 = ChannelFactoryTest.createTestChannel(user.getOrg());
        Channel ch2 = ChannelFactoryTest.createTestChannel(user.getOrg());

        Optional<Channel> baseChannel = Optional.of(base);
        Set<Channel> channels = new HashSet<>();
        channels.add(ch1);
        channels.add(ch2);
        Set<Action> actions = ActionChainManager.scheduleSubscribeChannelsAction(user,
                Collections.singleton(srvr.getId()),
                baseChannel,
                channels,
                new Date(), null);

        Action action = actions.stream().findFirst().get();

        assertInstanceOf(SubscribeChannelsAction.class, action);
        SubscribeChannelsAction sca = (SubscribeChannelsAction)action;

        HibernateFactory.getSession().flush();
        HibernateFactory.getSession().clear();

        Map<String, Object> params = new HashMap<>();
        params.put("details_id", sca.getDetails().getId());
        DataResult dr = TestUtils.runTestQuery("action_subscribe_channels_list", params);
        assertEquals(2, dr.size());

        Action action2 = ActionFactory.lookupById(action.getId());
        assertInstanceOf(SubscribeChannelsAction.class, action2);
        SubscribeChannelsAction sca2 = (SubscribeChannelsAction)action2;
        assertEquals(base.getId(), sca2.getDetails().getBaseChannel().getId());
        assertEquals(2, sca2.getDetails().getChannels().size());
        assertTrue(sca2.getDetails().getChannels().stream().anyMatch(c -> c.getId().equals(ch1.getId())));
        assertTrue(sca2.getDetails().getChannels().stream().anyMatch(c -> c.getId().equals(ch2.getId())));
        // tokens are generated right when executing the action
        assertEquals(0, sca2.getDetails().getAccessTokens().size());
        assertEquals(1, action2.getServerActions().size());
    }

    @Test
    public void testScheduleImageBuild() throws Exception {
        TaskomaticApi taskomaticMock = mock(TaskomaticApi.class);
        ActionChainManager.setTaskomaticApi(taskomaticMock);
        ImageInfoFactory.setTaskomaticApi(taskomaticMock);

        MinionServer server = MinionServerFactoryTest.createTestMinionServer(user);
        systemEntitlementManager.addEntitlementToServer(server, EntitlementManager.CONTAINER_BUILD_HOST);
        ImageStore store = createImageStore("registry.reg", user);
        ActivationKey ak = createActivationKey(user);
        ImageProfile prof = createImageProfile("myprofile", store, ak, user);
        ActionChain actionChain = ActionChainFactory.createActionChain("my-test-ac", user);

        ImageBuildAction action = ActionChainManager.scheduleImageBuild(server.getId(),
                "1.0.0",
                prof,
                new Date(),
                actionChain, user);

        assertNotNull(action);
        assertEquals("Build an Image Profile", action.getActionType().getName());
    }

    @Test
    public void testDefineApplyStatesActionName() {
        List<String> states = List.of("util.syncgrains", "hardware.profileupdate", "util.syncmodules");
        String highstateNonRecurring = ActionManager.defineStatesActionName(Collections.emptyList(), false);
        String highstateRecurring = ActionManager.defineStatesActionName(Collections.emptyList(), true);
        String statesNonRecurring = ActionManager.defineStatesActionName(states, false);
        String statesRecurring = ActionManager.defineStatesActionName(states, true);
        assertEquals("Apply highstate", highstateNonRecurring);
        assertEquals("Apply recurring highstate", highstateRecurring);
        assertEquals("Apply recurring states [util.syncgrains, hardware.profileupdate, util.syncmodules]",
                statesRecurring);
        assertEquals("Apply states [util.syncgrains, hardware.profileupdate, util.syncmodules]", statesNonRecurring);
    }


    public static void assertNotEmpty(Collection coll) {
        assertNotNull(coll);
        if (coll.isEmpty()) {
            fail("Collection is empty");
        }
    }

    public void aTestSchedulePackageDelta() throws Exception {
        Server srvr = ServerFactory.lookupById(1005385254L);
        RhnSetDecl.PACKAGES_FOR_SYSTEM_SYNC.get(user);

        List<PackageListItem> a = new ArrayList<>();
        PackageListItem pli = new PackageListItem();
        pli.setIdCombo("3427|195967");
        pli.setEvrId(195967L);
        pli.setName("apr");
        pli.setRelease("0.4");
        pli.setNameId(3427L);
        pli.setEvr("0.9.5-0.4");
        pli.setVersion("0.9.5");
        pli.setEpoch(null);
        a.add(pli);

        pli = new PackageListItem();
        pli.setIdCombo("23223|196372");
        pli.setEvrId(196372L);
        pli.setName("bcel");
        pli.setRelease("1jpp_2rh");
        pli.setNameId(23223L);
        pli.setEvr("5.1-1jpp_2rh:0");
        pli.setVersion("5.1");
        pli.setEpoch("0");
        a.add(pli);

        pli = new PackageListItem();
        pli.setIdCombo("500000103|250840");
        pli.setEvrId(250840L);
        pli.setName("aspell");
        pli.setRelease("25.1");
        pli.setNameId(500000103L);
        pli.setEvr("0.33.7.1-25.1:2");
        pli.setVersion("0.33.7.1");
        pli.setEpoch("2");
        a.add(pli);

        List<PackageListItem> b = new ArrayList<>();
        pli = new PackageListItem();
        pli.setIdCombo("26980|182097");
        pli.setEvrId(182097L);
        pli.setName("asm");
        pli.setRelease("2jpp");
        pli.setNameId(26980L);
        pli.setEvr("1.4.1-2jpp:0");
        pli.setVersion("1.4.1");
        pli.setEpoch("0");
        b.add(pli);

        pli = new PackageListItem();
        pli.setIdCombo("500000103|271970");
        pli.setEvrId(271970L);
        pli.setName("aspell");
        pli.setRelease("25.3");
        pli.setNameId(500000103L);
        pli.setEvr("0.33.7.1-25.3:2");
        pli.setVersion("0.33.7.1");
        pli.setEpoch("2");
        b.add(pli);

        pli = new PackageListItem();
        pli.setIdCombo("23223|700004953");
        pli.setEvrId(700004953L);
        pli.setName("bcel");
        pli.setRelease("10");
        pli.setNameId(23223L);
        pli.setEvr("5.0-10");
        pli.setVersion("5.0");
        pli.setEpoch(null);
        b.add(pli);

        List<PackageMetadata> pkgs = ProfileManager.comparePackageLists(new DataResult<>(a),
                new DataResult<>(b), "foo");

        for (PackageMetadata pm : pkgs) {
            log.warn("pm [{}] compare [{}] release [{}]", pm.toString(), pm.getComparison(),
                    pm.getSystem() != null ? pm.getSystem().getRelease() : pm.getOther().getRelease());
        }

        Action action = ActionManager.schedulePackageRunTransaction(user, srvr, pkgs,
                new Date());
        System.out.println("Action is an [" + action.getClass().getName() + "]");
    }

    private TaskomaticApi getTaskomaticApi() throws TaskomaticApiException {
        if (taskomaticApi == null) {
            taskomaticApi = context.mock(TaskomaticApi.class);
            context.checking(new Expectations() {
                {
                    allowing(taskomaticApi).scheduleActionExecution(with(any(Action.class)));
                }
            });
        }

        return taskomaticApi;
    }
}
