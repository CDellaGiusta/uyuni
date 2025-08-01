/*
 * Copyright (c) 2012--2020 SUSE LLC
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
package com.redhat.rhn.frontend.action.systems;

import com.redhat.rhn.GlobalInstanceHolder;
import com.redhat.rhn.common.localization.LocalizationService;
import com.redhat.rhn.common.util.DatePicker;
import com.redhat.rhn.common.util.DynamicComparator;
import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.action.ActionFactory;
import com.redhat.rhn.domain.action.dup.DistUpgradeAction;
import com.redhat.rhn.domain.action.dup.DistUpgradeActionDetails;
import com.redhat.rhn.domain.action.dup.DistUpgradeChannelTask;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.ChannelArch;
import com.redhat.rhn.domain.channel.ChannelFactory;
import com.redhat.rhn.domain.channel.ClonedChannel;
import com.redhat.rhn.domain.product.SUSEProduct;
import com.redhat.rhn.domain.product.SUSEProductFactory;
import com.redhat.rhn.domain.product.SUSEProductSet;
import com.redhat.rhn.domain.rhnpackage.PackageFactory;
import com.redhat.rhn.domain.server.MinionServer;
import com.redhat.rhn.domain.server.MinionServerFactory;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.dto.ChildChannelDto;
import com.redhat.rhn.frontend.dto.EssentialChannelDto;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.manager.channel.ChannelManager;
import com.redhat.rhn.manager.distupgrade.DistUpgradeManager;
import com.redhat.rhn.manager.distupgrade.DistUpgradePaygException;
import com.redhat.rhn.manager.errata.ErrataManager;
import com.redhat.rhn.manager.rhnpackage.PackageManager;

import com.suse.manager.maintenance.NotInMaintenanceModeException;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.struts.action.ActionErrors;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.apache.struts.action.DynaActionForm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Action class for scheduling distribution upgrades (Product Migrations).
 */
public class SPMigrationAction extends RhnAction {

    private static Logger logger = LogManager.getLogger(SPMigrationAction.class);

    // Request attributes
    private static final String UPGRADE_SUPPORTED = "upgradeSupported";
    private static final String ZYPP_INSTALLED = "zyppPluginInstalled";
    private static final String MIGRATION_SCHEDULED = "migrationScheduled";
    private static final String LATEST_SP = "latestServicePack";
    private static final String MISSING_SUCCESSOR_EXTENSIONS = "missingSuccessorExtensions";
    private static final String TARGET_PRODUCTS = "targetProducts";

    private static final String NO_MAINTENANCE_WINDOW = "noMaintenanceWindow";
    private static final String CHANNEL_MAP = "channelMap";
    private static final String UPDATESTACK_UPDATE_NEEDED = "updateStackUpdateNeeded";
    private static final String IS_MINION = "isMinion";
    private static final String IS_SUSE_MINION = "isSUSEMinion";
    private static final String IS_REDHAT_MINION = "isRedHatMinion";
    private static final String IS_SALT_UP_TO_DATE = "isSaltUpToDate";
    private static final String SALT_PACKAGE = "saltPackage";
    private static final String HAS_DRYRUN_CAPABLITY = "hasDryRunCapability";

    // Form parameters
    private static final String ACTION_STEP = "step";
    private static final String SETUP = "setup";
    private static final String TARGET = "target";
    private static final String CONFIRM = "confirm";
    private static final String SCHEDULE = "schedule";
    private static final String BASE_PRODUCT = "baseProduct";
    private static final String ADDON_PRODUCTS = "addonProducts";
    private static final String BASE_CHANNEL = "baseChannel";
    private static final String CHILD_CHANNELS = "childChannels";
    private static final String TARGET_PRODUCT_SELECTED = "targetProductSelected";
    private static final String ALLOW_VENDOR_CHANGE = "allowVendorChange";

    // Message keys
    private static final String DISPATCH_DRYRUN = "spmigration.jsp.confirm.submit.dry-run";
    private static final String GO_BACK = "spmigration.jsp.confirm.back";
    private static final String MSG_SCHEDULED_MIGRATION = "spmigration.message.scheduled";
    private static final String MSG_SCHEDULED_DRYRUN =
            "spmigration.message.scheduled.dry-run";
    private static final String MSG_ERROR_PAYG_MIGRATION = "spmigration.message.payg.error";

    /**
     * {@inheritDoc}
     */
    @Override
    public ActionForward execute(ActionMapping actionMapping,
                                 ActionForm actionForm, HttpServletRequest request,
                                 HttpServletResponse response) throws Exception {
        // Bind the server object to the request
        RequestContext ctx = new RequestContext(request);
        Server server = ctx.lookupAndBindServer();

        DynaActionForm form = (DynaActionForm) actionForm;
        String actionStep = TARGET;

        // Called after redirect from event history after running a product migration dry-run
        if (ctx.hasParam("aid")) {
            DatePicker picker = getStrutsDelegate().prepopulateDatePicker(request, form,
                    "date", DatePicker.YEAR_RANGE_POSITIVE);
            request.setAttribute("date", picker);
            return actionMapping.findForward(populateRequestFromAction(request, ctx));
        }

        Optional<MinionServer> minion = MinionServerFactory.lookupById(server.getId());
        // Check if this server is a minion
        boolean isMinion = minion.isPresent();
        logger.debug("is a minion system? {}", isMinion);
        request.setAttribute(IS_MINION, isMinion);

        // Check if this is a SUSE system (for minions only)
        boolean isSUSEMinion = isMinion && minion.get().isOsFamilySuse();
        logger.debug("is a SUSE minion? {}", isSUSEMinion);
        request.setAttribute(IS_SUSE_MINION, isSUSEMinion);

        // Check if this is a RedHat system (for minions only)
        boolean isRedHatMinion = isMinion && minion.get().getOsFamily().equals("RedHat");
        logger.debug("is a RedHat minion? {}", isRedHatMinion);
        request.setAttribute(IS_REDHAT_MINION, isRedHatMinion);

        // Check if the salt package on the minion is up to date (for minions only)
        String saltPackage = "salt";
        if (PackageFactory.lookupByNameAndServer("venv-salt-minion", server) != null) {
            saltPackage = "venv-salt-minion";
        }
        boolean isSaltUpToDate = PackageManager.
                getServerNeededUpdatePackageByName(server.getId(), saltPackage) == null;
        logger.debug("salt package is up-to-date? {}", isSaltUpToDate);
        request.setAttribute(IS_SALT_UP_TO_DATE, isSaltUpToDate);
        request.setAttribute(SALT_PACKAGE, saltPackage);

        // Check if this server supports distribution upgrades via capabilities
        // (for traditional clients only)
        boolean supported = isSUSEMinion || isRedHatMinion ||
                DistUpgradeManager.isUpgradeSupported(server, ctx.getCurrentUser());
        logger.debug("Upgrade supported for '{}'? {}", server.getName(), supported);
        request.setAttribute(UPGRADE_SUPPORTED, supported);

        // Check if zypp-plugin-spacewalk is installed (for traditional clients only)
        boolean zyppPluginInstalled = PackageFactory.lookupByNameAndServer(
                "zypp-plugin-spacewalk", server) != null;
        logger.debug("zypp plugin installed? {}", zyppPluginInstalled);
        request.setAttribute(ZYPP_INSTALLED, zyppPluginInstalled);

        // Check if the newest update stack is installed (for traditional clients only)
        boolean updateStackUpdateNeeded = ErrataManager.updateStackUpdateNeeded(
                ctx.getCurrentUser(), server);
        logger.debug("update stack update needed? {}", updateStackUpdateNeeded);
        request.setAttribute(UPDATESTACK_UPDATE_NEEDED, updateStackUpdateNeeded);


        // Check if there is already a migration in the schedule
        Action migration = null;
        if (supported) {
            migration = ActionFactory.isMigrationScheduledForServer(server.getId());
        }
        request.setAttribute(MIGRATION_SCHEDULED, migration);

        // Init request parameters
        Long targetBaseProduct = null;
        Long[] targetAddonProducts = null;
        Long targetBaseChannel = null;
        Long[] targetChildChannels = null;
        boolean dryRun = false;
        boolean hasDryRun = true;
        boolean goBack = false;
        boolean targetProductSelectedEmpty = false;
        boolean allowVendorChange = false;

        String targetProductSelected = request.getParameter(TARGET_PRODUCT_SELECTED);

        // Read form parameters if dispatching
        String dispatch = request.getParameter(RequestContext.DISPATCH);
        if (dispatch != null) {
            actionStep = (String) form.get(ACTION_STEP);

            // Get target product and channel IDs
            targetBaseProduct = (Long) form.get(BASE_PRODUCT);
            targetAddonProducts = (Long[]) form.get(ADDON_PRODUCTS);
            targetBaseChannel = (Long) form.get(BASE_CHANNEL);
            targetChildChannels = (Long[]) form.get(CHILD_CHANNELS);
            allowVendorChange = BooleanUtils.isTrue((Boolean)form.get(ALLOW_VENDOR_CHANGE));

            // Get additional flags
            if (dispatch.equals(LocalizationService.getInstance().getMessage(DISPATCH_DRYRUN))) {
                dryRun = true;
            }

            // flag to know if we are going back or forward in the setup wizard
            goBack = dispatch.equals(LocalizationService.getInstance().getMessage(GO_BACK));

            // flag to know if we should show the dry-run button or not
            String bpProductClass = minion.map(m -> m.getInstalledProductSet()
                    .map(i -> i.getBaseProduct().getChannelFamily().getLabel())
                    .orElse("")).orElse("");

            String tgtProductClass = Optional.ofNullable(targetBaseProduct)
                    .map(SUSEProductFactory::getProductById)
                    .map(s -> s.getChannelFamily().getLabel())
                    .orElse("");

            hasDryRun = !isRedHatMinion && bpProductClass.equals(tgtProductClass);
            request.setAttribute(HAS_DRYRUN_CAPABLITY, hasDryRun);

        }

        // if submitting step 1 (TARGET) but no radio button
        // for target migration selected, return step 1 (TARGET)
        if (dispatch != null && actionStep.equals(TARGET) && targetProductSelected == null) {
            targetProductSelectedEmpty = true;
            dispatch = null;
        }
        request.setAttribute("targetProductSelectedEmpty", targetProductSelectedEmpty);

        // Find the action forward
        ActionForward forward = findForward(actionMapping, actionStep, dispatch, goBack);

        // Put data to the request
        if (forward.getName().equals(TARGET) && supported && migration == null) {
            // Find target products
            Optional<SUSEProductSet> installedProducts = server.getInstalledProductSet();
            if (installedProducts.isEmpty()) {
                // Installed products are 'unknown'
                logger.debug("Installed products are 'unknown'");
                return forward;
            }
            installedProducts.ifPresent(pset -> {
                logger.debug(pset.toString());
                if (pset.getBaseProduct() == null) {
                    logger.error("Server: {} has no base product installed. Check your servers installed products.",
                            server.getId());
                }
            });
            List<SUSEProductSet> migrationTargets = getMigrationTargets(
                    request,
                    installedProducts,
                    server.getServerArch().getCompatibleChannelArch(),
                    ctx.getCurrentUser()
            );

            if (migrationTargets.isEmpty()) {
                // Latest SP is apparently installed
                logger.debug("Latest SP is apparently installed");
                request.setAttribute(LATEST_SP, true);
                return forward;
            }
            else if (!migrationTargets.isEmpty()) {
                // At least one target available
                logger.debug("Found at least one migration target");
                request.setAttribute(TARGET_PRODUCTS, migrationTargets);
            }
        }
        else if (forward.getName().equals(SETUP)) {
            // Find target products
            Optional<SUSEProductSet> installedProducts = server.getInstalledProductSet();
            ChannelArch arch = server.getServerArch().getCompatibleChannelArch();
            List<SUSEProductSet> migrationTargets = DistUpgradeManager.
                    getTargetProductSets(installedProducts,
                            server.getServerArch().getCompatibleChannelArch(),
                            ctx.getCurrentUser());

            // Get and decode the target product selected to migrate
            SUSEProductSet targetProducts = new SUSEProductSet();
            for (SUSEProductSet target : migrationTargets) {
                if (target.getSerializedProductIDs()
                        .equals(targetProductSelected)) {
                    targetProducts = target;
                }
            }
            request.setAttribute(TARGET_PRODUCTS, targetProducts);
            setMissingSuccessorsInfo(request, installedProducts, List.of(targetProducts));

            // Get the base channel
            Channel suseBaseChannel = DistUpgradeManager.getProductBaseChannel(
                    targetProducts.getBaseProduct().getId(), arch, ctx.getCurrentUser());

            // Determine mandatory channels
            List<EssentialChannelDto> requiredChannels =
                    DistUpgradeManager.getRequiredChannels(
                            targetProducts, suseBaseChannel.getId());

            // Get available alternatives
            SortedMap<ClonedChannel, List<Long>> alternatives = DistUpgradeManager.
                    getAlternatives(targetProducts, arch, ctx.getCurrentUser());

            // Create new map, put original channels first
            HashMap<Channel, List<ChildChannelDto>> channelMap =
                    new LinkedHashMap<>();
            channelMap.put(suseBaseChannel, getChildChannels(
                    suseBaseChannel, ctx, server, extractIDs(requiredChannels)));

            // Put cloned alternatives
            for (ClonedChannel alternative : alternatives.keySet()) {
                channelMap.put(alternative, getChildChannels(
                        alternative, ctx, server, alternatives.get(alternative)));
            }

            // Put all channel data to the request
            request.setAttribute(CHANNEL_MAP, channelMap);
        }
        else if (forward.getName().equals(CONFIRM)) {
            setConfirmAttributes(request, ctx, server, form, targetBaseProduct, targetAddonProducts,
                    targetBaseChannel, targetChildChannels, allowVendorChange);
        }
        else if (forward.getName().equals(SCHEDULE)) {
            // Create target product set from parameters
            SUSEProductSet targetProductSet = createProductSet(targetBaseProduct, targetAddonProducts);

            // Setup list of channels to subscribe to
            List<Long> channelIDs = new ArrayList<>();
            if (targetChildChannels != null) {
                channelIDs.addAll(Arrays.asList(targetChildChannels));
            }
            channelIDs.add(targetBaseChannel);

            // Schedule the dist upgrade action
            Date earliest = getStrutsDelegate().readScheduleDate(form, "date",
                    DatePicker.YEAR_RANGE_POSITIVE);
            try {
                Long actionID = DistUpgradeManager.scheduleDistUpgrade(ctx.getCurrentUser(),
                        server, targetProductSet, channelIDs, dryRun, allowVendorChange, earliest,
                        GlobalInstanceHolder.PAYG_MANAGER.isPaygInstance());

                // Display a message to the user
                String product = targetProductSet.getBaseProduct().getFriendlyName();
                String msgKey = dryRun ? MSG_SCHEDULED_DRYRUN : MSG_SCHEDULED_MIGRATION;
                String[] msgParams = new String[]{server.getId().toString(), actionID.toString(), product};
                getStrutsDelegate().saveMessage(msgKey, msgParams, request);
                Map<String, Long> params = new HashMap<>();
                params.put("sid", server.getId());
                return getStrutsDelegate().forwardParams(forward, params);
            }
            catch (NotInMaintenanceModeException e) {
                setConfirmAttributes(request, ctx, server, form, targetBaseProduct, targetAddonProducts,
                        targetBaseChannel, targetChildChannels, allowVendorChange);
                request.setAttribute(NO_MAINTENANCE_WINDOW, true);
                forward = actionMapping.findForward(CONFIRM);
            }
            catch (DistUpgradePaygException e) {
                Optional<SUSEProductSet> installedProducts = server.getInstalledProductSet();
                List<SUSEProductSet> migrationTargets = getMigrationTargets(
                        request,
                        installedProducts,
                        server.getServerArch().getCompatibleChannelArch(),
                        ctx.getCurrentUser()
                );
                request.setAttribute(TARGET_PRODUCTS, migrationTargets);

                ActionErrors errors = new ActionErrors();
                // We do not support migration with individual channels in UI. So we only
                // need 1 error message as the second case can only happens in API
                getStrutsDelegate().addError(errors, MSG_ERROR_PAYG_MIGRATION);
                getStrutsDelegate().saveMessages(request, errors);

                forward = actionMapping.findForward(TARGET);
            }
        }

        return forward;
    }

    /**
     * Set in the request the parameters for the confirm forward. Public only for testing
     *
     * @param request - the request
     * @param ctx - request context
     * @param server - the server
     * @param form - dyna form
     * @param targetBaseProduct - target base product
     * @param targetAddonProducts - target addon products
     * @param targetBaseChannel - target base channel
     * @param targetChildChannels - target child channels
     * @param allowVendorChange - allow vendor change
     */
    public void setConfirmAttributes(
            HttpServletRequest request,
            RequestContext ctx,
            Server server,
            DynaActionForm form,
            Long targetBaseProduct,
            Long[] targetAddonProducts,
            Long targetBaseChannel,
            Long[] targetChildChannels,
            boolean allowVendorChange
    ) {
        // Put product data
        SUSEProductSet targetProductSet = createProductSet(targetBaseProduct, targetAddonProducts);
        setMissingSuccessorsInfo(request,  server.getInstalledProductSet(), List.of(targetProductSet));
        request.setAttribute(TARGET_PRODUCTS, targetProductSet);
        request.setAttribute(BASE_PRODUCT, targetProductSet.getBaseProduct());
        request.setAttribute(ADDON_PRODUCTS, targetProductSet.getAddonProducts());
        request.setAttribute(ALLOW_VENDOR_CHANGE, allowVendorChange);
        // Put channel data
        Channel baseChannel = ChannelFactory.lookupByIdAndUser(targetBaseChannel, ctx.getCurrentUser());
        request.setAttribute(BASE_CHANNEL, baseChannel);
        // Add those child channels that will be subscribed
        List<EssentialChannelDto> childChannels = getChannelDTOs(ctx, baseChannel,
                Arrays.asList(targetChildChannels));
        request.setAttribute(CHILD_CHANNELS, childChannels);

        // Pre-populate the date picker
        DatePicker picker = getStrutsDelegate().prepopulateDatePicker(request, form,
                "date", DatePicker.YEAR_RANGE_POSITIVE);
        request.setAttribute("date", picker);
    }

    /**
     * Identify the extensions which don't have successors and set that information in the request.
     * OUT: MISSING_SUCESSOR_EXTENSIONS
     * @param request
     * @param sourceProducts installed or selected products
     * @param targetProducts target products
     */
    private void setMissingSuccessorsInfo(HttpServletRequest request, Optional<SUSEProductSet> sourceProducts,
                                          List<SUSEProductSet> targetProducts) {
        Optional<Set<String>> missingSuccessorExtensions = Optional.of(new HashSet<String>());
        DistUpgradeManager.removeIncompatibleTargets(sourceProducts,
                targetProducts, missingSuccessorExtensions);
        request.setAttribute(MISSING_SUCCESSOR_EXTENSIONS, missingSuccessorExtensions.orElse(new HashSet<String>()));
    }

    /**
     * Find the destination given the current page and the dispatch string.
     * The order of actions is: TARGET -> SETUP -> CONFIRM -> SCHEDULE.
     * @param mapping
     * @param wizardStep
     * @param dispatch
     * @return
     */
    private ActionForward findForward(ActionMapping mapping, String wizardStep,
            String dispatch, boolean goBack) {
        if (dispatch == null) {
            return mapping.findForward(TARGET);
        }

        ActionForward forward;
        if (wizardStep.equals(TARGET)) {
            forward = mapping.findForward(SETUP);
        }
        else if (wizardStep.equals(SETUP)) {
            forward = goBack ? mapping.findForward(TARGET) : mapping.findForward(CONFIRM);
        }
        else if (wizardStep.equals(CONFIRM)) {
            forward = goBack ? mapping.findForward(SETUP) : mapping.findForward(SCHEDULE);
        }
        else {
            // Unknown wizard step, go to setup
            forward = mapping.findForward(TARGET);
        }
        return forward;
    }

    /**
     * Create a list of all child channels of a given base channel as
     * {@link ChildChannelDto} objects.
     * @param baseChannel
     * @param ctx
     * @param s
     * @param requiredChannels
     * @return
     */
    private List<ChildChannelDto> getChildChannels(Channel baseChannel,
            RequestContext ctx, Server s, List<Long> requiredChannels) {
        User user = ctx.getCurrentUser();
        List<Channel> channels = baseChannel.getAccessibleChildrenFor(user);

        // Sort channels by name
        channels.sort(new DynamicComparator<>("name", RequestContext.SORT_ASC));

        List<ChildChannelDto> childChannels = new ArrayList<>();
        for (Channel child : channels) {
            ChildChannelDto childChannel = new ChildChannelDto(child.getId(),
                    child.getName(),
                    s.isSubscribed(child),
                    child.isSubscribable(user.getOrg(), s));

            // Mark required channels as mandatory
            childChannel.setMandatory(requiredChannels.contains(childChannel.getId()));

            childChannels.add(childChannel);
        }
        return childChannels;
    }

    /**
     * Create a list of channels as given by their IDs and their base channel.
     * @param ctx
     * @param baseChannel
     * @param channelIDs
     * @return List of channels
     */
    private List<EssentialChannelDto> getChannelDTOs(RequestContext ctx,
            Channel baseChannel, List<Long> channelIDs) {
        List<Channel> childChannels = baseChannel.getAccessibleChildrenFor(ctx.getCurrentUser());

        // Sort channels by name
        childChannels.sort(new DynamicComparator<>("name", RequestContext.SORT_ASC));

        List<EssentialChannelDto> channelDTOs = new ArrayList<>();
        for (Channel child : childChannels) {
            if (channelIDs.contains(child.getId())) {
                EssentialChannelDto dto = new EssentialChannelDto(child);
                channelDTOs.add(dto);
            }
        }
        return channelDTOs;
    }

    /**
     * Create a {@link SUSEProductSet} from IDs given as {@link Long}s.
     * @param baseProduct
     * @param addonProducts
     * @return set of SUSE products
     */
    private SUSEProductSet createProductSet(Long baseProduct, Long[] addonProducts) {
        List<Long> addonProductsList = new ArrayList<>();
        if (addonProducts != null) {
            addonProductsList.addAll(Arrays.asList(addonProducts));
        }
        return new SUSEProductSet(baseProduct, addonProductsList);
    }

    /**
     * Extract IDs of all entries in a given list of {@link EssentialChannelDto}
     * objects.
     * @param channels
     * @return list of the channel IDs
     */
    private List<Long> extractIDs(List<EssentialChannelDto> channels) {
        List<Long> channelIDs = new ArrayList<>();
        for (EssentialChannelDto c : channels) {
            channelIDs.add(c.getId());
        }
        return channelIDs;
    }

    /**
     * Gets a list of valid migration targets for given ProductSet.
     * Filters out extensions missing a successor and populates MISSING_SUCCESSOR_EXTENSIONS.
     * OUT: MISSING_SUCESSOR_EXTENSIONS
     *
     * @param request the HttpServletRequest
     * @param installedProducts SUSEProductSet containing installed products
     * @param channelArch architecture of the server
     * @param user the user
     * @return list containing available migration targets
     */
    private List<SUSEProductSet> getMigrationTargets(HttpServletRequest request,
                                                     Optional<SUSEProductSet> installedProducts,
                                                     ChannelArch channelArch,
                                                     User user) {
        List<SUSEProductSet> allMigrationTargets = DistUpgradeManager.
                getTargetProductSets(installedProducts, channelArch, user);
        setMissingSuccessorsInfo(request, installedProducts, allMigrationTargets);
        return allMigrationTargets;
    }

    /**
     * Populate the request attributes from a given action
     *
     * @param request the HttpServletRequest
     * @param ctx the RequestContext
     * @return String containing the ActionForward target
     */
    private String populateRequestFromAction(HttpServletRequest request, RequestContext ctx) {
        Long aid = ctx.getParamAsLong("aid");

        DistUpgradeAction action = (DistUpgradeAction) ActionFactory.lookupById(aid);
        DistUpgradeActionDetails details = action.getDetails();
        List<Channel> channels = details.getChannelTasks().stream()
                .filter(channel -> channel.getTask() == DistUpgradeChannelTask.SUBSCRIBE)
                .map(DistUpgradeChannelTask::getChannel)
                .toList();

        Set<Channel> baseChannelSet = channels.stream()
                .filter(Channel::isBaseChannel)
                .collect(Collectors.toSet());

        if (baseChannelSet.size() != 1) {
            logger.debug("{}matching base channels found", baseChannelSet.isEmpty() ? "No " : "Multiple ");
            return TARGET;
        }

        Channel baseChannel = baseChannelSet.iterator().next();
        List<Long> channelIds = channels.stream().map(Channel::getId).collect(Collectors.toList());
        List<EssentialChannelDto> childChannels = getChannelDTOs(ctx, baseChannel, channelIds);

        // Get name of original base channel if channel is cloned
        String origBaseChannelName = ChannelManager.getOriginalChannel(baseChannel).getName();
        SUSEProduct baseProduct = SUSEProductFactory.lookupByChannelName(origBaseChannelName).get(0).getRootProduct();

        Server server = ctx.lookupAndBindServer();
        Optional<SUSEProductSet> installedProducts = server.getInstalledProductSet();
        List<SUSEProductSet> targetProductSet = getMigrationTargets(
                request,
                installedProducts,
                server.getServerArch().getCompatibleChannelArch(),
                ctx.getCurrentUser()
        ).stream().filter(productSet -> productSet.getBaseProduct().equals(baseProduct)).collect(Collectors.toList());

        if (targetProductSet.isEmpty()) {
            logger.debug("No valid migration target found");
            return TARGET;
        }
        else if (targetProductSet.size() > 1) {
            logger.warn("Multiple migration targets found: {}", targetProductSet);
        }
        else {
            request.setAttribute(ADDON_PRODUCTS, targetProductSet.get(0).getAddonProducts());
        }

        request.setAttribute(TARGET_PRODUCTS, targetProductSet.get(0));
        request.setAttribute(BASE_PRODUCT, targetProductSet.get(0).getBaseProduct());

        request.setAttribute(BASE_CHANNEL, baseChannel);
        request.setAttribute(CHILD_CHANNELS, childChannels);
        request.setAttribute(ALLOW_VENDOR_CHANGE, details.isAllowVendorChange());

        return CONFIRM;
    }
}
