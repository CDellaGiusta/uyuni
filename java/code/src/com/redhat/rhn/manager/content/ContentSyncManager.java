/*
 * Copyright (c) 2014--2021 SUSE LLC
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
package com.redhat.rhn.manager.content;

import com.redhat.rhn.GlobalInstanceHolder;
import com.redhat.rhn.common.conf.Config;
import com.redhat.rhn.common.conf.ConfigDefaults;
import com.redhat.rhn.common.hibernate.HibernateFactory;
import com.redhat.rhn.common.util.TimeUtils;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.ChannelFactory;
import com.redhat.rhn.domain.channel.ChannelFamily;
import com.redhat.rhn.domain.channel.ChannelFamilyFactory;
import com.redhat.rhn.domain.channel.ContentSource;
import com.redhat.rhn.domain.channel.PublicChannelFamily;
import com.redhat.rhn.domain.cloudpayg.PaygProductFactory;
import com.redhat.rhn.domain.cloudpayg.PaygSshDataFactory;
import com.redhat.rhn.domain.common.ManagerInfoFactory;
import com.redhat.rhn.domain.credentials.CloudRMTCredentials;
import com.redhat.rhn.domain.credentials.CredentialsFactory;
import com.redhat.rhn.domain.credentials.RemoteCredentials;
import com.redhat.rhn.domain.credentials.SCCCredentials;
import com.redhat.rhn.domain.iss.IssFactory;
import com.redhat.rhn.domain.product.ChannelTemplate;
import com.redhat.rhn.domain.product.MgrSyncChannelDto;
import com.redhat.rhn.domain.product.ProductType;
import com.redhat.rhn.domain.product.ReleaseStage;
import com.redhat.rhn.domain.product.SUSEProduct;
import com.redhat.rhn.domain.product.SUSEProductChannel;
import com.redhat.rhn.domain.product.SUSEProductExtension;
import com.redhat.rhn.domain.product.SUSEProductFactory;
import com.redhat.rhn.domain.product.Tuple2;
import com.redhat.rhn.domain.product.Tuple3;
import com.redhat.rhn.domain.rhnpackage.PackageArch;
import com.redhat.rhn.domain.rhnpackage.PackageFactory;
import com.redhat.rhn.domain.scc.SCCCachingFactory;
import com.redhat.rhn.domain.scc.SCCOrderItem;
import com.redhat.rhn.domain.scc.SCCRepository;
import com.redhat.rhn.domain.scc.SCCRepositoryAuth;
import com.redhat.rhn.domain.scc.SCCRepositoryBasicAuth;
import com.redhat.rhn.domain.scc.SCCRepositoryNoAuth;
import com.redhat.rhn.domain.scc.SCCRepositoryTokenAuth;
import com.redhat.rhn.domain.scc.SCCSubscription;
import com.redhat.rhn.domain.server.MinionServer;
import com.redhat.rhn.domain.server.ServerFactory;
import com.redhat.rhn.frontend.xmlrpc.sync.content.ContentSyncSource;
import com.redhat.rhn.frontend.xmlrpc.sync.content.ContentSyncSourceException;
import com.redhat.rhn.frontend.xmlrpc.sync.content.LocalDirContentSyncSource;
import com.redhat.rhn.frontend.xmlrpc.sync.content.RMTContentSyncSource;
import com.redhat.rhn.frontend.xmlrpc.sync.content.SCCContentSyncSource;
import com.redhat.rhn.manager.channel.ChannelManager;
import com.redhat.rhn.taskomatic.task.payg.beans.PaygProductInfo;

import com.suse.cloud.CloudPaygManager;
import com.suse.manager.hub.HubManager;
import com.suse.manager.model.hub.HubFactory;
import com.suse.manager.model.hub.IssHub;
import com.suse.manager.webui.services.pillar.MinionGeneralPillarGenerator;
import com.suse.mgrsync.MgrSyncStatus;
import com.suse.salt.netapi.parser.JsonParser;
import com.suse.scc.SCCEndpoints;
import com.suse.scc.client.SCCClient;
import com.suse.scc.client.SCCClientException;
import com.suse.scc.client.SCCClientUtils;
import com.suse.scc.client.SCCConfig;
import com.suse.scc.client.SCCWebClient;
import com.suse.scc.model.ChannelFamilyJson;
import com.suse.scc.model.SCCOrderItemJson;
import com.suse.scc.model.SCCOrderJson;
import com.suse.scc.model.SCCProductJson;
import com.suse.scc.model.SCCRepositoryJson;
import com.suse.scc.model.SCCSubscriptionJson;
import com.suse.utils.Opt;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Content synchronization logic.
 */
public class ContentSyncManager {

    // Logger instance
    private static final Logger LOG = LogManager.getLogger(ContentSyncManager.class);

    /**
     * OES channel family name, this is used to distinguish supported non-SUSE
     * repos that are served directly from NCC instead of SCC.
     */
    public static final String OES_CHANNEL_FAMILY = "OES2";
    private static final String OES_URL = "https://nu.novell.com/repo/$RCE/OES2023-Pool/sle-15-x86_64/";

    // Static JSON files we parse
    private static File channelFamiliesJson = new File(
            "/usr/share/susemanager/scc/channel_families.json");
    private static File additionalProductsJson = new File(
            "/usr/share/susemanager/scc/additional_products.json");
    private static File additionalRepositoriesJson = new File(
            "/usr/share/susemanager/scc/additional_repositories.json");

    // File to parse this system's UUID from
    private static final File UUID_FILE = new File("/etc/zypp/credentials.d/SCCcredentials");
    private static String uuid;

    // Mirror URL read from rhn.conf
    public static final String MIRROR_CFG_KEY = "server.susemanager.mirror";

    // SCC JSON files location in rhn.conf
    public static final String RESOURCE_PATH = "server.susemanager.fromdir";

    private Optional<File> sumaProductTreeJson = Optional.empty();

    private CloudPaygManager cloudPaygManager;

    private final HubFactory hubFactory;

    private final boolean isPeripheral;
    private final boolean hubHasSignedMetadata;

    private final List<String> toolsChannelFamilies;

    private final Path tmpLoggingDir;

    /**
     * Default constructor.
     */
    public ContentSyncManager() {
        this(Paths.get(SCCConfig.DEFAULT_LOGGING_DIR), GlobalInstanceHolder.PAYG_MANAGER);
    }

    /**
     * @param tmpLogDir logdir for credential output
     * @param paygMgrIn {@link CloudPaygManager} to use
     */
    public ContentSyncManager(Path tmpLogDir, CloudPaygManager paygMgrIn) {
        cloudPaygManager = paygMgrIn;
        tmpLoggingDir = tmpLogDir;
        hubFactory = new HubFactory();
        Optional<IssHub> issHub = hubFactory.lookupIssHub();
        isPeripheral = issHub.isPresent();
        hubHasSignedMetadata = StringUtils.isNotBlank(issHub.map(IssHub::getGpgKey).orElse(""));
        toolsChannelFamilies = new ArrayList<>();
        toolsChannelFamilies.add(ChannelFamilyFactory.TOOLS_CHANNEL_FAMILY_LABEL);
        if (Config.get().getString(ConfigDefaults.PRODUCT_TREE_TAG, "").equals("Beta")) {
            String betaClass = ChannelFamilyFactory.TOOLS_CHANNEL_FAMILY_LABEL + "-BETA";
            toolsChannelFamilies.add(betaClass);
        }
    }

    /**
     * @return return a stream of statically defined upgrade paths not coming from SCC.
     */
    protected Stream<Tuple2<Long, Long>> staticUpgradePaths() {
        Set<Tuple2<Long, Long>> upgradePaths = Set.of(
                new Tuple2<>(-7L, 2702L), // rhel-base-7-None.x86_64 => res-ltss-7-None.x86_64
                new Tuple2<>(-12L, 2702L), // centos-7-None.x86_64 => res-ltss-7-None.x86_64
                new Tuple2<>(-12L, 1251L), // centos-7-None.x86_64 => res-7-None.x86_64
                new Tuple2<>(-14L, 2702L), // oraclelinux-7-None.x86_64 => res-7-None.x86_64
                new Tuple2<>(-14L, 2778L), // oraclelinux-7-None.x86_64 => res-ol-ltss-7-None.x86_64
                new Tuple2<>(-17L, -8L), // oraclelinux-8-None.x86_64 => rhel-base-8-None.x86_64
                new Tuple2<>(-24L, -8L), // rockylinux-8-None.x86_64 => rhel-base-8-None.x86_64
                new Tuple2<>(-26L, -8L), // almalinux-8-None.x86_64  => rhel-base-8-None.x86_64
                new Tuple2<>(-41L, -35L), // oraclelinux-9-None.x86_64 => el-base-9-None.x86_64
                new Tuple2<>(-36L, -35L), // rockylinux-9-None.x86_64 => el-base-9-None.x86_64
                new Tuple2<>(-38L, -35L) // almalinux-9-None.x86_64 => el-base-9-None.x86_64
        );
        return upgradePaths.stream();
    }

    /**
     * Set the channel_family.json {@link File} to a different path.
     * @param file the channel_family.json
     */
    public static void setChannelFamiliesJson(File file) {
        channelFamiliesJson = file;
    }

    /**
     * Set the product_tree.json {@link File} to read from.
     * @param file the product_tree.json file
     */
    public void setSumaProductTreeJson(Optional<File> file) {
        sumaProductTreeJson = file;
    }

    /**
     * Set the additional_products.json {@link File} to read from.
     * @param file the add additional_products.json file
     */
    public static void setAdditionalProductsJson(File file) {
        additionalProductsJson = file;
    }

    /**
     * Read the channel_families.json file.
     *
     * @return List of parsed channel families
     */
    public List<ChannelFamilyJson> readChannelFamilies() {
        Gson gson = new GsonBuilder().create();
        List<ChannelFamilyJson> channelFamilies = new ArrayList<>();
        try {
            channelFamilies = gson.fromJson(new BufferedReader(new InputStreamReader(
                            new FileInputStream(channelFamiliesJson))),
                    SCCClientUtils.toListType(ChannelFamilyJson.class));
        }
        catch (IOException e) {
            LOG.error(e.getMessage(), e);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Read {} channel families from {}", channelFamilies.size(),
                    channelFamiliesJson.getAbsolutePath());
        }
        return channelFamilies;
    }

    /**
     * There can be no network credentials, but still can read the local files
     * As well as we do need to read the file only once.
     * If /etc/rhn/rhn.conf contains local path URL, then the SCCClient will read
     * from the local file instead of the network.
     * @return List of {@link ContentSyncSource}
     */
    private List<ContentSyncSource> filterCredentials() throws ContentSyncException {
        Optional<List<ContentSyncSource>> local = ConfigDefaults.get().getOfflineMirrorDir()
                        .map(p -> List.of(new LocalDirContentSyncSource(Paths.get(p))));

        // We prefer local mirror over scc over cloud rmt
        return local
            .or(() -> Optional.of(CredentialsFactory.listSCCCredentials())
                .filter(cs -> !cs.isEmpty())
                .map(cs -> cs.stream().map(SCCContentSyncSource::new).collect(Collectors.toList()))
            )
            .or(() -> Optional.of(cloudPaygManager)
                .filter(paygManager -> paygManager.isPaygInstance())
                .flatMap(paygManager -> PaygSshDataFactory.lookupCloudCredentialsByHostname("localhost"))
                .flatMap(c -> c.castAs(CloudRMTCredentials.class))
                .map(c -> List.of(new RMTContentSyncSource(c)))
            )
            .orElseThrow(() -> new ContentSyncException("No SCC organization credentials found."));
    }

    /**
     * Returns all products available to all configured credentials.
     * @return list of all available products
     * @throws ContentSyncException in case of an error
     */
    public List<SCCProductJson> getProducts() throws ContentSyncException {
        List<ContentSyncSource> sources = filterCredentials();

        List<SCCProductJson> sccProductJsons = sources.stream().map(source -> {
                    try {
                        SCCClient scc = getSCCClient(source);
                        var products = scc.listProducts();
                        products.forEach(product -> {
                            // Check for missing attributes
                            String missing = verifySCCProduct(product);
                            if (!StringUtils.isBlank(missing)) {
                                LOG.warn("Broken product: {}, Version: {}, Identifier: {}, Product ID: {} " +
                                                "### Missing attributes: {}", product.getName(), product.getVersion(),
                                        product.getIdentifier(), product.getId(), missing);
                            }
                        });
                        return products;
                    }
                    catch (SCCClientException e) {
                        // test for OES credentials
                        return handleOESCredentials(source, e, Collections::<SCCProductJson>emptyList);
                    }
                })
                .filter(products -> !products.isEmpty())
                // stop as soon as a credential pair works
                .findFirst()
                .orElseGet(Collections::emptyList);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Found {} available products.", sccProductJsons.size());
        }

        return sccProductJsons;
    }

    /**
     * @return the list of additional repositories (aka fake repositories) we
     * defined in the sumatoolbox which are not part of SCC. Those fake repos come from
     * 2 places.
     *  - the additional_repositories.json which contains a list of fake repos.
     *  - the additional_products.json which contains fake products which may also contain
     *    additional fake repositories.
     */
    private static List<SCCRepositoryJson> getAdditionalRepositories() {
        Gson gson = new GsonBuilder().create();
        List<SCCRepositoryJson> repos = new ArrayList<>();
        try {
            repos = gson.fromJson(new BufferedReader(new InputStreamReader(
                            new FileInputStream(additionalRepositoriesJson))),
                    SCCClientUtils.toListType(SCCRepositoryJson.class));
        }
        catch (IOException e) {
            LOG.error(e.getMessage(), e);
        }
        repos.addAll(collectRepos(flattenProducts(getAdditionalProducts()).collect(Collectors.toList())));
        return repos;
    }

    /*
     * Return static list or OES products
     */
    private static List<SCCProductJson> getAdditionalProducts() {
        Gson gson = new GsonBuilder().create();
        List<SCCProductJson> additionalProducts = new ArrayList<>();
        try {
            additionalProducts = gson.fromJson(new BufferedReader(new InputStreamReader(
                            new FileInputStream(additionalProductsJson))),
                    SCCClientUtils.toListType(SCCProductJson.class));
        }
        catch (IOException e) {
            LOG.error(e.getMessage(), e);
        }
        return additionalProducts;
    }

    /**
     * Returns all available products in user-friendly format.
     * @return list of all available products
     */
    public List<MgrSyncProductDto> listProducts() {
        if (!(ConfigDefaults.get().isUyuni() || hasToolsChannelSubscription() || canSyncToolsChannelViaCloudRMT())) {
            LOG.warn("No SUSE Multi-Linux Manager Server Subscription available. " +
                    "Products requiring Client Tools Channel will not be shown.");
        }
        return HibernateFactory.doWithoutAutoFlushing(this::listProductsImpl);
    }

    /**
     * Verify suseProductChannel is present for all synced channels, if not re-add it.
     */
    public void ensureSUSEProductChannelData() {
        List<Channel> syncedChannels = ChannelFactory.listVendorChannels();
        for (Channel sc : syncedChannels) {
            List<SUSEProductChannel> spcList = SUSEProductFactory.lookupSyncedProductChannelsByLabel(sc.getLabel());
            if (spcList.isEmpty()) {
                List<ChannelTemplate> missing = SUSEProductFactory.lookupChannelTemplateByChannelLabel(sc.getLabel());
                missing.forEach(md -> {
                    SUSEProductChannel correctedData = new SUSEProductChannel();
                    correctedData.setProduct(md.getProduct());
                    correctedData.setChannel(sc);
                    correctedData.setMandatory(md.isMandatory());
                    SUSEProductFactory.save(correctedData);
                });
            }
        }
    }

    /**
     * Returns all available products in user-friendly format.
     * @return list of all available products
     */
    private List<MgrSyncProductDto> listProductsImpl() {
        List<String> installedChannelLabels = getInstalledChannelLabels();

        List<Tuple2<ChannelTemplate, MgrSyncStatus>> availableChannels =
                TimeUtils.logTime(LOG, "getAvailableChannels", () -> getAvailableChannels()).stream().map(e -> {
                    MgrSyncStatus status = installedChannelLabels.contains(e.getChannelLabel()) ?
                            MgrSyncStatus.INSTALLED : MgrSyncStatus.AVAILABLE;
                    return new Tuple2<>(e, status);
                }).toList();

        List<SUSEProduct> allSUSEProducts = SUSEProductFactory.findAllSUSEProducts();

        List<SUSEProduct> roots = allSUSEProducts.stream()
                .filter(SUSEProduct::isBase)
                .toList();

        Map<Long, List<Long>> recommendedForBase = SUSEProductFactory.allRecommendedExtensions().stream().collect(
                Collectors.groupingBy(
                        s -> s.getExtensionProduct().getProductId(),
                        Collectors.mapping(s -> s.getRootProduct().getProductId(), Collectors.toList())
                )
        );


        Map<Long, List<Tuple2<ChannelTemplate, MgrSyncStatus>>> byProductId = availableChannels.stream()
                .collect(Collectors.groupingBy(p -> p.getA().getProduct().getId()));
        Map<Long, List<Tuple2<ChannelTemplate, MgrSyncStatus>>> byRootId = availableChannels.stream()
                .collect(Collectors.groupingBy(p -> p.getA().getRootProduct().getId()));

        return roots.stream()
                .filter(p -> byProductId.containsKey(p.getId()))
                .map(root -> {

                    var exts = byRootId.get(root.getId()).stream()
                            .filter(p -> !p.getA().getProduct().equals(root));

                    var repos = byProductId.get(root.getId());

                    var partitionBaseRepo = repos.stream()
                            .collect(Collectors.partitioningBy(p -> p.getA().getParentChannelLabel() == null));

                    var baseRepos = partitionBaseRepo.get(true).stream()
                        // for RHEL and Vmware which have multiple base channels for a product
                        .sorted(Comparator.comparing(a -> a.getA().getChannelLabel()));

                    List<Tuple2<ChannelTemplate, MgrSyncStatus>> childRepos = partitionBaseRepo.get(false);

                    Set<MgrSyncChannelDto> allChannels = childRepos.stream().map(c -> new MgrSyncChannelDto(
                            c.getA().getChannelName(),
                            c.getA().getChannelLabel(),
                            c.getA().getProduct().getFriendlyName(),
                            c.getA().getRepository().getDescription(),
                            c.getA().isMandatory(),
                            c.getA().getRepository().isInstallerUpdates(),
                            Optional.ofNullable(c.getA().getProduct().getArch()),
                            c.getA().getParentChannelLabel(),
                            c.getA().getProduct().getChannelFamily().getLabel(),
                            c.getA().getProduct().getName(),
                            c.getA().getProduct().getVersion(),
                            c.getB(),
                            c.getA().getRepository().isSigned(),
                            c.getA().getRepository().getUrl(),
                            c.getA().getUpdateTag()
                    )).collect(Collectors.toSet());

                    List<MgrSyncChannelDto> baseChannels = baseRepos.map(baseRepo -> new MgrSyncChannelDto(
                            baseRepo.getA().getChannelName(),
                            baseRepo.getA().getChannelLabel(),
                            baseRepo.getA().getProduct().getFriendlyName(),
                            baseRepo.getA().getRepository().getDescription(),
                            baseRepo.getA().isMandatory(),
                            baseRepo.getA().getRepository().isInstallerUpdates(),
                            Optional.ofNullable(baseRepo.getA().getProduct().getArch()),
                            baseRepo.getA().getParentChannelLabel(),
                            baseRepo.getA().getProduct().getChannelFamily().getLabel(),
                            baseRepo.getA().getProduct().getName(),
                            baseRepo.getA().getProduct().getVersion(),
                            baseRepo.getB(),
                            baseRepo.getA().getRepository().isSigned(),
                            baseRepo.getA().getRepository().getUrl(),
                            baseRepo.getA().getUpdateTag()
                    )).toList();
                    allChannels.addAll(baseChannels);
                    MgrSyncChannelDto baseChannel = baseChannels.get(0);

                    var byExtension = exts.collect(Collectors.groupingBy(e -> e.getA().getProduct()));

                    Set<MgrSyncProductDto> extensions = byExtension.entrySet().stream().map(e -> {
                        SUSEProduct ext = e.getKey();

                        Set<MgrSyncChannelDto> extChildChannels = e.getValue().stream().map(c -> new MgrSyncChannelDto(
                                c.getA().getChannelName(),
                                c.getA().getChannelLabel(),
                                c.getA().getProduct().getFriendlyName(),
                                c.getA().getRepository().getDescription(),
                                c.getA().isMandatory(),
                                c.getA().getRepository().isInstallerUpdates(),
                                Optional.ofNullable(c.getA().getProduct().getArch()),
                                c.getA().getParentChannelLabel(),
                                c.getA().getProduct().getChannelFamily().getLabel(),
                                c.getA().getProduct().getName(),
                                c.getA().getProduct().getVersion(),
                                c.getB(),
                                c.getA().getRepository().isSigned(),
                                c.getA().getRepository().getUrl(),
                                c.getA().getUpdateTag()
                        )).collect(Collectors.toSet());

                        boolean isRecommended = Optional.ofNullable(recommendedForBase.get(ext.getProductId()))
                                .map(s -> s.contains(root.getProductId()))
                                .orElse(false);

                        return new MgrSyncProductDto(
                                ext.getFriendlyName(), ext.getProductId(), ext.getId(), ext.getVersion(), isRecommended,
                                baseChannel, extChildChannels, Collections.emptySet()
                        );
                    }).collect(Collectors.toSet());

                    return new MgrSyncProductDto(
                            root.getFriendlyName(), root.getProductId(), root.getId(), root.getVersion(), false,
                            baseChannel, allChannels, extensions);
                }).collect(Collectors.toList());
    }

    /**
     * Refresh the repositories cache by reading repos from SCC for all available mirror
     * credentials, consolidating and inserting into the database.
     *
     * Two possible modes:
     * 1. Online - mirror from SCC or a specified optional mirror
     * 2. Offline - "fromdir" configured - everything must come from there
     *
     * Credential NULL defines Offline mode
     *
     * @throws ContentSyncException in case of an error
     */
    private void refreshRepositoriesAuthentication(String mirrorUrl, boolean excludeSCC) throws ContentSyncException {

        ChannelFactory.cleanupOrphanVendorContentSource();

        try {
            // Query repos for all mirror credentials and consolidate
            filterCredentials().stream()
                .filter(source -> !excludeSCC || !(source instanceof SCCContentSyncSource))
                .forEach(source -> {
                    LOG.debug("Getting repos for: {}", source);
                    List<SCCRepositoryJson> repos = source.match(
                        scc -> {
                            try {
                                SCCClient client = getSCCClient(source);
                                return client.listRepositories();
                            }
                            catch (SCCClientException e) {
                                // test for OES credentials
                                SCCCredentials cred = scc.getCredentials(SCCCredentials.class)
                                    .orElseThrow(() -> new ContentSyncException("Invalid credentials type"));

                                if (!accessibleUrl(OES_URL, cred.getUsername(), cred.getPassword())) {
                                    LOG.info("Credential is not an OES credentials");
                                    throw new ContentSyncException(e);
                                }
                                return Collections.emptyList();
                            }
                        },
                        // cloudrmt does not support the scc repository endpoint
                        cloudrmt -> {
                            LOG.info("Getting credentials");
                            var cred = cloudrmt.getCredentials(CloudRMTCredentials.class)
                                .orElseThrow(() -> new ContentSyncException("Invalid credentials type"));

                            LOG.info("Retrieving products");
                            // Retrieve the products associated with this credentials
                            List<PaygProductInfo> productsList = PaygProductFactory.getProductsForCredentials(cred);
                            // If it's SUMA PAYG, check if we synced additional products we can access
                            LOG.info("Checking suma payg");
                            if (cred.getPaygSshData().isSUSEManagerPayg()) {
                                LOG.info("Adding additional products");
                                productsList.addAll(PaygProductFactory.listAdditionalProductsForSUMAPayg());
                            }

                            LOG.info("Refreshing PAYG auth");
                            List<SCCRepositoryAuth> repoAuths = PaygProductFactory
                                .refreshRepositoriesAuths(cred, productsList);
                            LOG.info("Refreshed {} repository auths associated to the PAYG credentials",
                                repoAuths.size());
                            return Collections.emptyList();
                        },
                        localdir -> {
                            try {
                                SCCClient client = getSCCClient(source);
                                return client.listRepositories();
                            }
                            catch (SCCClientException e) {
                                throw new ContentSyncException(e);
                            }
                        }
                    );

                    LinkedList<SCCRepositoryJson> allReposList = new LinkedList<>(repos);
                    allReposList.addAll(getAdditionalRepositories());
                    refreshRepositoriesAuthentication(allReposList, source, mirrorUrl);
                });
        }
        finally {
            ensureSUSEProductChannelData();
            linkAndRefreshContentSource(mirrorUrl);
            ManagerInfoFactory.setLastMgrSyncRefresh();
        }
    }

    /**
     * Create or update a ContentSource.
     * @param auth a repository authentication object to use
     * @param channel the channel
     * @param mirrorUrl optional mirror URL
     */
    public void createOrUpdateContentSource(SCCRepositoryAuth auth, Channel channel, String mirrorUrl) {
        ContentSource source = auth.getContentSource();

        if (source == null) {
            String url = contentSourceUrlOverwrite(auth.getRepo(), auth.getUrl(), mirrorUrl);
            source = Optional.ofNullable(ChannelFactory.findVendorContentSourceByRepo(url))
                    .orElse(new ContentSource());
            source.setLabel(channel.getLabel());
            source.setMetadataSigned(auth.getRepo().isSigned());
            source.setOrg(null);
            source.setSourceUrl(url);
            source.setType(ChannelManager.findCompatibleContentSourceType(channel.getChannelArch()));
            ChannelFactory.save(source);
        }
        Set<ContentSource> css = channel.getSources();
        css.add(source);
        channel.setSources(css);
        ChannelFactory.save(channel);
        auth.setContentSource(source);
    }

    private void linkOrphanContentSource(ContentSource cs) {
        for (Channel c : cs.getChannels()) {
            ChannelFactory.findVendorRepositoryByChannel(c).ifPresentOrElse(
                    repo -> repo.getBestAuth().ifPresentOrElse(
                            auth -> {
                                LOG.debug("Has new auth: {}", cs.getLabel());
                                auth.setContentSource(cs);
                                SCCCachingFactory.saveRepositoryAuth(auth);
                            },
                            () -> {
                                LOG.debug("No auth anymore - remove content source: {}", cs.getLabel());
                                c.getSources().remove(cs);
                                ChannelFactory.remove(cs);
                            }
                    ),
                    () -> {
                        LOG.debug("No repository found for channel: '{}' - remove content source", cs.getLabel());
                        c.getSources().remove(cs);
                        ChannelFactory.remove(cs);
                    }
            );
        }
    }

    /**
     * Search for orphan contentsource or channels and try to find
     * available repositories. In case they are found they get linked.
     *
     * @param mirrorUrl optional mirror url
     */
    public void linkAndRefreshContentSource(String mirrorUrl) {
        LOG.debug("linkAndRefreshContentSource called");
        // flush needed to let the next queries find something
        HibernateFactory.getSession().flush();
        // find all CountentSource with org id == NULL which do not have a sccrepositoryauth
        List<ContentSource> orphan = ChannelFactory.lookupOrphanVendorContentSources();
        if (!orphan.isEmpty()) {
            LOG.debug("found orphan vendor content sources: {}", orphan.size());
            // find sccrepositoryauth and link
            for (ContentSource cs : orphan) {
                linkOrphanContentSource(cs);
            }
            HibernateFactory.getSession().flush();
        }
        // find all rhnChannel with org id == null and no content source
        List<Channel> orphanChannels = ChannelFactory.lookupOrphanVendorChannels();
        if (!orphanChannels.isEmpty()) {
            LOG.debug("found orphan vendor channels: {}", orphanChannels.size());
            // find sccrepository auth and create content source and link
            orphanChannels.forEach(c -> Opt.consume(ChannelFactory.findVendorRepositoryByChannel(c),
                    () -> LOG.error("No repository found for channel: '{}'", c.getLabel()),
                    repo -> {
                        LOG.debug("configure orphan repo {}", repo);
                        repo.getBestAuth().ifPresentOrElse(
                                a -> createOrUpdateContentSource(a, c, mirrorUrl),
                                () -> LOG.info("No Auth available for {}", repo)
                        );
                    }
            ));
        }
        // update URL if needed
        for (SCCRepositoryAuth auth : SCCCachingFactory.lookupRepositoryAuthWithContentSource()) {
            boolean save = false;
            ContentSource cs = auth.getContentSource();

            // check if this auth item is the "best" available auth for this repo
            // if not, switch it over to the best
            Optional<SCCRepositoryAuth> bestAuthOpt = auth.getRepo().getBestAuth();
            if (bestAuthOpt.isEmpty()) {
                LOG.warn("no best auth available for repo {}", auth.getRepo());
                continue;
            }
            SCCRepositoryAuth bestAuth = bestAuthOpt.get();
            if (!bestAuth.equals(auth)) {
                // we are not the "best" available repository auth item.
                // remove the content source link and set it to the "best"
                LOG.info("Auth '{}' became the best auth. Remove CS link from {}", bestAuth.getId(), auth.getId());
                auth.setContentSource(null);
                bestAuth.setContentSource(cs);
                SCCCachingFactory.saveRepositoryAuth(auth);
                SCCCachingFactory.saveRepositoryAuth(bestAuth);
                // and continue with the best
                auth = bestAuth;
            }
            String overwriteUrl = contentSourceUrlOverwrite(auth.getRepo(), auth.getUrl(), mirrorUrl);
            LOG.debug("Linked ContentSource: '{}' OverwriteURL: '{}' AuthUrl: '{}' Mirror: '{}'",
                    cs.getSourceUrl(), overwriteUrl, auth.getUrl(), mirrorUrl);
            if (!cs.getSourceUrl().equals(overwriteUrl)) {
                LOG.debug("Change URL to : {}", overwriteUrl);
                cs.setSourceUrl(overwriteUrl);
                save = true;
            }
            if (cs.getMetadataSigned() != auth.getRepo().isSigned()) {
                cs.setMetadataSigned(auth.getRepo().isSigned());
                save = true;
            }
            if (save) {
                ChannelFactory.save(cs);
            }
        }
    }

    /**
     * Return true if a refresh of Product Data is needed
     *
     * @param mirrorUrl a mirrorURL
     * @return true if a refresh is needed, otherwise false
     */
    public boolean isRefreshNeeded(String mirrorUrl) {
        for (SCCRepositoryAuth a : SCCCachingFactory.lookupRepositoryAuthWithContentSource()) {
            ContentSource cs = a.getContentSource();
            try {
                String overwriteUrl = contentSourceUrlOverwrite(a.getRepo(), a.getUrl(), mirrorUrl);
                LOG.debug("Linked ContentSource: '{}' OverwriteURL: '{}' AuthUrl: '{}' Mirror: {}",
                        cs.getSourceUrl(), overwriteUrl, a.getUrl(), mirrorUrl);
                if (!cs.getSourceUrl().equals(overwriteUrl)) {
                    LOG.debug("Source and overwrite urls differ: {} != {}", cs.getSourceUrl(), overwriteUrl);
                    return true;
                }
            }
            catch (ContentSyncException e) {
                if (cloudPaygManager.isPaygInstance()) {
                    LOG.debug("PAYG instance detected. Continue checking for refresh needed.");
                    break;
                }
                // Can happen when neither SCC Credentials nor fromdir is configured
                // in such a case, refresh makes no sense.
                return false;
            }
        }

        Optional<Date> lastRefreshDate = ManagerInfoFactory.getLastMgrSyncRefresh();
        if (Config.get().getString(ContentSyncManager.RESOURCE_PATH, null) != null) {
            LOG.debug("Syncing from dir");
            long hours24 = 24 * 60 * 60 * 1000;
            Timestamp t = new Timestamp(System.currentTimeMillis() - hours24);

            return Opt.fold(
                    lastRefreshDate,
                    () -> true,
                    modifiedCache -> {
                        LOG.debug("Last sync more than 24 hours ago: {} ({})", modifiedCache, t);
                        return t.after(modifiedCache);
                    }
            );
        }
        else if (CredentialsFactory.listSCCCredentials().isEmpty() && !(cloudPaygManager.isPaygInstance() &&
                PaygSshDataFactory.lookupByHostname("localhost").isPresent())) {
            // Can happen when neither SCC Credentials nor fromdir is configured
            // Also when we are PAYG instance, but localhost connection is not configured
            // in such a case, refresh makes no sense.
            return false;
        }
        return SCCCachingFactory.refreshNeeded(lastRefreshDate);
    }

    private Optional<SCCRepositoryAuth> determineAuth(SCCRepositoryJson jrepo, SCCRepository repo,
                                                      ContentSyncSource c) {

        String url = c.castAs(LocalDirContentSyncSource.class)
            .map(LocalDirContentSyncSource.class::cast)
            // "fromdir" - convert into local file URL
            .map(local -> MgrSyncUtils.urlToFSPath(jrepo.getUrl(), repo.getName(), local.getPath()).toString())
            .orElse(jrepo.getUrl());

        Optional<String> tokenOpt = getTokenFromURL(url);

        //SCC
        //Token auth
        if (tokenOpt.isPresent()) {
            return Optional.of(new SCCRepositoryTokenAuth(tokenOpt.get()));
        }
        //BOTH
        //Not in product tree
        else if (repo.getChannelTemplates().isEmpty()) {
            LOG.debug("Repo '{}' not in the product tree. Skipping", repo.getUrl());
            return Optional.empty();
        }
        //SCC
        //Not Local Dir and free product (to avoid expensive accessibleUrl check for free products)
        else if (!(c instanceof LocalDirContentSyncSource) &&
                repo.getChannelTemplates().stream()
                        .map(ChannelTemplate::getProduct)
                        //TODO: check what free means in scc and if it works for us
                        .filter(SUSEProduct::getFree)
                        .anyMatch(p -> {
                            String cfLabel = p.getChannelFamily().getLabel();
                            return cfLabel.startsWith(ChannelFamilyFactory.TOOLS_CHANNEL_FAMILY_LABEL) ||
                                    cfLabel.startsWith(ChannelFamilyFactory.OPENSUSE_CHANNEL_FAMILY_LABEL);
                        })) {
            LOG.debug("Free repo detected. Setting NoAuth for {}", repo.getUrl());
            return Optional.of(new SCCRepositoryNoAuth());
        }


        else {

            try {
                List<String> fullUrls = buildRepoFileUrls(url, repo);
                //Try without credentials
                // also tests fromdir
                if (accessibleUrl(fullUrls)) {
                    URI uri = new URI(url);
                    if (uri.getUserInfo() == null) {
                        return Optional.of(new SCCRepositoryNoAuth());
                    }
                    else {
                        // we do not handle the case where the credentials are part of the URL
                        LOG.error("URLs with credentials not supported");
                        return Optional.empty();
                    }
                }
                // Not LocalDir accessible with credentials
                else if (c.getCredentials(SCCCredentials.class)
                    .map(scc -> accessibleUrl(fullUrls, scc.getUsername(), scc.getPassword()))
                    .orElse(false)) {
                    return Optional.of(new SCCRepositoryBasicAuth());
                }
                else {
                    // typical happens with fromdir where not all repos are synced
                    LOG.warn("url: {} not accessible.", fullUrls);
                    return Optional.empty();
                }
            }
            catch (URISyntaxException e) {
                LOG.warn("Unable to parse URL: {}", e.getMessage());
                return Optional.empty();
            }

        }
    }

    /**
     * Update authentication for all repos of the given credential.
     * Removes authentication if they have expired
     *
     * @param repositories the new repositories
     * @param source the credentials
     * @param mirrorUrl optional mirror url
     */
    public void refreshRepositoriesAuthentication(
            Collection<SCCRepositoryJson> repositories, ContentSyncSource source, String mirrorUrl) {
        List<Long> repoIdsFromCredential = new LinkedList<>();
        List<Long> availableRepoIds = SCCCachingFactory.lookupRepositories().stream()
                .map(SCCRepository::getSccId)
                .toList();
        Map<Boolean, List<SCCRepositoryJson>> ptfOrCustomRepos = repositories.stream()
                .filter(r -> !availableRepoIds.contains(r.getSCCId()))
                .collect(Collectors.groupingBy(SCCRepositoryJson::isPtfRepository,
                        Collectors.toList()));

        generatePtfChannels(ptfOrCustomRepos.getOrDefault(Boolean.TRUE, Collections.emptyList()));
        Map<Long, SCCRepository> availableReposById = SCCCachingFactory.lookupRepositories().stream()
                .collect(Collectors.toMap(SCCRepository::getSccId, r -> r));

        List<SCCRepositoryAuth> allExistingRepoAuths = SCCCachingFactory.lookupRepositoryAuth();

        // cloudrmt and mirror work together
        // mirror and scc doesn't work together
        //CLEANUP
        if (source instanceof LocalDirContentSyncSource) {
            // cleanup if we come from scc
            allExistingRepoAuths.stream()
                    .filter(a -> a.getOptionalCredentials().isPresent())
                    .filter(a -> a.cloudRmtAuth().isEmpty())
                    .forEach(SCCCachingFactory::deleteRepositoryAuth);
        }
        else {
            // cleanup if we come from "fromdir"
            allExistingRepoAuths.stream()
                    .filter(a -> a.getOptionalCredentials().isEmpty())
                    .filter(a -> a.cloudRmtAuth().isEmpty())
                    .forEach(SCCCachingFactory::deleteRepositoryAuth);
        }

        //REPO HANDLING
        List<SCCRepository> oesRepos = SCCCachingFactory.lookupRepositoriesByChannelFamily(OES_CHANNEL_FAMILY);
        List<SCCRepositoryJson> nonOESJRepos = repositories.stream()
                .filter(jsonRepo -> oesRepos.stream().noneMatch(oes -> oes.getSccId().equals(jsonRepo.getSCCId())))
                .filter(jsonRepo -> !jsonRepo.getSCCId().equals(SCCEndpoints.CUSTOM_REPO_FAKE_SCC_ID))
                .toList();

        for (SCCRepositoryJson jsonRepo : nonOESJRepos) {
            SCCRepository repo = availableReposById.get(jsonRepo.getSCCId());
            if (repo == null) {
                LOG.error("No repository with ID '{}' found", jsonRepo.getSCCId());
                // This happens when no ChannelTemplate reference this repository
                continue;
            }
            Set<SCCRepositoryAuth> allRepoAuths = repo.getRepositoryAuth();
            Set<SCCRepositoryAuth> authsThisCred = allRepoAuths.stream()
                    .filter(a -> {
                        if (source instanceof LocalDirContentSyncSource) {
                            return a.getOptionalCredentials().isEmpty();
                        }
                        else {
                            Optional<RemoteCredentials> oc = a.getOptionalCredentials();
                            return oc.isPresent() && oc.equals(source.getCredentials());
                        }
                    })
                    .collect(Collectors.toSet());

            if (authsThisCred.size() > 1) {
                LOG.error("More than 1 authentication found for one credential - removing all unused");
                authsThisCred.forEach(a -> {
                    allRepoAuths.remove(a);
                    authsThisCred.remove(a);
                    SCCCachingFactory.deleteRepositoryAuth(a);
                });
                repo.setRepositoryAuth(allRepoAuths);
            }

            determineAuth(jsonRepo, repo, source).ifPresent(newAuth -> {
                repoIdsFromCredential.add(jsonRepo.getSCCId());
                authsThisCred.stream().findFirst().ifPresentOrElse(exAuth -> {
                    // Auth exists - check if we need to update it
                    Opt.and(exAuth.tokenAuth(), newAuth.tokenAuth()).ifPresentOrElse(t -> {
                        SCCRepositoryTokenAuth exTAuth = t.getA();
                        SCCRepositoryTokenAuth newTAuth = t.getB();
                        if (!exTAuth.getAuth().equals(newTAuth.getAuth())) {
                            exTAuth.setAuth(newTAuth.getAuth());
                            SCCCachingFactory.saveRepositoryAuth(exTAuth);
                            ContentSource updateCS = exTAuth.getContentSource();
                            if (updateCS != null) {
                                updateCS.setMetadataSigned(repo.isSigned());
                                updateCS.setSourceUrl(contentSourceUrlOverwrite(repo, exTAuth.getUrl(), mirrorUrl));
                                ChannelFactory.save(updateCS);
                            }
                        }
                    }, () -> {
                        // other types are basic and no auth which differ only in the type
                        if (!exAuth.getClass().equals(newAuth.getClass())) {
                            // class differ => remove and later add
                            source.getCredentials().ifPresent(newAuth::setCredentials);
                            newAuth.setRepo(repo);
                            SCCCachingFactory.saveRepositoryAuth(newAuth);
                            allRepoAuths.add(newAuth);
                            allRepoAuths.remove(exAuth);
                            repo.setRepositoryAuth(allRepoAuths);
                            SCCCachingFactory.deleteRepositoryAuth(exAuth);
                        }
                    });
                    // else => unchanged, nothing to do
                }, () -> {
                    // We need to create a new auth for this repo
                    source.getCredentials().ifPresent(newAuth::setCredentials);
                    newAuth.setRepo(repo);
                    allRepoAuths.add(newAuth);
                    repo.setRepositoryAuth(allRepoAuths);
                    SCCCachingFactory.saveRepositoryAuth(newAuth);
                });
            });

        }

        // OES
        source.getCredentials(SCCCredentials.class)
            .ifPresent(scc -> repoIdsFromCredential.addAll(refreshOESRepositoryAuth(scc, mirrorUrl, oesRepos)));

        // Custom Channels
        source.getCredentials(SCCCredentials.class)
            .ifPresent(scc -> refreshCustomRepoAuthentication(
                    ptfOrCustomRepos.getOrDefault(Boolean.FALSE, Collections.emptyList()), scc));

        //DELETE OLD
        // check if we have to remove auths which exists before
        List<SCCRepositoryAuth> authList = SCCCachingFactory.lookupRepositoryAuthByCredential(source);
        authList.stream()
                .filter(repoAuth -> repoAuth.cloudRmtAuth().isEmpty()) // rmtAuth is handled elsewhere (where?)
                .filter(repoAuth -> !repoIdsFromCredential.contains(repoAuth.getRepo().getSccId()))
                .forEach(a -> {
                    a.getRepo().getRepositoryAuth().remove(a);
                    SCCCachingFactory.deleteRepositoryAuth(a);
                });
    }

    private void refreshCustomRepoAuthentication(List<SCCRepositoryJson> customReposIn, SCCCredentials creds) {
        IssHub issHub = creds.getIssHub();
        if (issHub == null) {
            LOG.debug("Only Peripheral server manage custom channels via SCC API");
            return;
        }
        Set<ContentSource> toDeleteCustomRepos = new HashSet<>(
                ChannelFactory.findCustomContentSourcesForHubFqdn(issHub.getFqdn()));

        for (SCCRepositoryJson repo : customReposIn) {
            Channel customChannel = ChannelFactory.lookupByLabel(repo.getName());
            if (!isValidCustomChannel(repo, customChannel)) {
                LOG.error("Invalid custom repo/channel {} - {}", repo, customChannel);
                return;
            }
            toDeleteCustomRepos.removeAll(customChannel.getSources());
            refreshOrCreateRepository(repo, customChannel, issHub);
        }
        toDeleteCustomRepos.forEach(ChannelFactory::remove);
    }

    /**
     * refresh or create a repositories when connected to a Hub
     *
     * @param repository SCCRepositoryJson objects {@link SCCRepositoryJson}
     * @param channel the channel for the repo
     * @param issHub {@link IssHub} to use
     */
    public void refreshOrCreateRepository(SCCRepositoryJson repository, Channel channel, IssHub issHub) {
        if (issHub == null) {
            LOG.debug("Only Peripheral server manage custom channels via SCC API");
            return;
        }
        boolean metadataSigned = StringUtils.isNotBlank(issHub.getGpgKey());
        Set<ContentSource> css = channel.getSources();
        if (css.isEmpty() && null == channel.getOrg()) {
            ContentSource vcss = ChannelFactory.findVendorContentSourceByRepo(repository.getUrl());
            if (vcss != null) {
                css.add(vcss);
            }
        }
        if (css.isEmpty()) {
            // new channel; need to add the source
            ContentSource source = new ContentSource();
            source.setLabel(channel.getLabel());
            source.setOrg(channel.getOrg());
            source.setSourceUrl(repository.getUrl());
            source.setType(ChannelManager.findCompatibleContentSourceType(channel.getChannelArch()));
            source.setMetadataSigned(metadataSigned);
            ChannelFactory.save(source);

            css.add(source);
            channel.setSources(css);
            ChannelFactory.save(channel);
        }
        else if (css.size() == 1) {
            // found the repo; update the URL
            ContentSource source = css.iterator().next();
            source.setSourceUrl(repository.getUrl());
            source.setMetadataSigned(metadataSigned);
            ChannelFactory.save(source);
        }
        else {
            LOG.error("Multiple repositories not allowed for this channel {}. Skipping",
                    channel.getName());
        }
    }

    private boolean isValidCustomChannel(SCCRepositoryJson repoIn, Channel customChannelIn) {
        return customChannelIn != null && repoIn != null &&
                Objects.equals(repoIn.getSCCId(), HubManager.CUSTOM_REPO_FAKE_SCC_ID) &&
                Objects.equals(customChannelIn.getLabel(), repoIn.getName());
    }

    private void generatePtfChannels(List<SCCRepositoryJson> repositories) {
        List<SCCRepository> reposToSave = new ArrayList<>();
        List<ChannelTemplate> templatesToSave = new ArrayList<>();
        for (SCCRepositoryJson jRepo : repositories) {
            PtfProductRepositoryInfo ptfInfo = parsePtfInfoFromUrl(jRepo);
            if (ptfInfo == null) {
                continue;
            }

            List<SUSEProduct> rootProducts = SUSEProductFactory.findAllRootProductsOf(ptfInfo.getProduct());
            if (rootProducts.isEmpty()) {
                // when no root product was found, we are the root product
                rootProducts.add(ptfInfo.getProduct());
            }

            rootProducts.stream()
                    .map(root -> convertToChannelTemplate(root, ptfInfo))
                    .filter(Objects::nonNull)
                    .forEach(templatesToSave::add);

            reposToSave.add(ptfInfo.getRepository());
        }

        reposToSave.forEach(SUSEProductFactory::save);
        templatesToSave.forEach(SUSEProductFactory::save);
    }

    private PtfProductRepositoryInfo parsePtfInfoFromUrl(SCCRepositoryJson jrepo) {
        URI uri;

        try {
            uri = new URI(jrepo.getUrl());
        }
        catch (URISyntaxException e) {
            LOG.warn("Unable to parse URL '{}'. Skipping", jrepo.getUrl(), e);
            return null;
        }

        // Format: /PTF/Release/<ACCOUNT>/<Product Identifier>/<Version>/<Architecture>/[ptf|test]
        String[] parts = uri.getPath().split("/");
        if (!(parts[1].equals("PTF") && parts[2].equals("Release"))) {
            return null;
        }
        String prdArch = parts[6];
        String archStr = switch (prdArch) {
            case "amd64" -> prdArch + "-deb";
            case "arm64" -> prdArch + "-deb";
            default -> prdArch;
        };

        SCCRepository repo = new SCCRepository();
        repo.setSigned(isRepoSigned(true));
        repo.update(jrepo);

        SUSEProduct product = SUSEProductFactory.findSUSEProduct(parts[4], parts[5], null, archStr, false);
        if (product == null) {
            LOG.warn("Skipping PTF repo for unknown product: {}", uri);
            return null;
        }

        List<String> channelParts = new ArrayList<>(Arrays.asList(parts[3], product.getName(), product.getVersion()));
        switch (parts[7]) {
            case "ptf":
                channelParts.add("PTFs");
                break;
            case "test":
                channelParts.add("TEST");
                break;
            default:
                LOG.warn("Unknown repo type: {}. Skipping", parts[7]);
                return null;
        }
        channelParts.add(prdArch);

        return new PtfProductRepositoryInfo(product, repo, channelParts, prdArch);
    }

    private static ChannelTemplate convertToChannelTemplate(SUSEProduct root, PtfProductRepositoryInfo ptfInfo) {
        ChannelTemplate template = new ChannelTemplate();

        template.setProduct(ptfInfo.getProduct());
        template.setRepository(ptfInfo.getRepository());
        template.setRootProduct(root);

        template.setUpdateTag(null);
        template.setMandatory(false);

        // Current PTF key for SLE 12/15 and SLE-Micro
        template.setGpgKeyUrl("file:///usr/lib/rpm/gnupg/keys/suse_ptf_key.asc");

        ptfInfo.getProduct()
                .getChannelTemplates()
                .stream()
                .filter(r -> r.getRootProduct().equals(root) && r.getParentChannelLabel() != null)
                .findFirst()
                .ifPresent(r -> {
                    List<String> suffix = new ArrayList<>();

                    template.setParentChannelLabel(r.getParentChannelLabel());
                    int archIdx = r.getChannelName().lastIndexOf(ptfInfo.getArchitecture());
                    if (archIdx > -1) {
                        suffix = Arrays.asList(
                                r.getChannelName().substring(archIdx + ptfInfo.getArchitecture().length())
                                        .strip().split("[\\s-]"));
                    }

                    List<String> cList = Stream.concat(ptfInfo.getChannelParts().stream(), suffix.stream())
                            .filter(e -> !e.isBlank())
                            .collect(Collectors.toList());

                    template.setChannelLabel(String.join("-", cList).toLowerCase().replaceAll("( for | )", "-"));
                    template.setChannelName(String.join(" ", cList));
                });
        if (StringUtils.isBlank(template.getChannelLabel())) {
            // mandatory field is missing. This happens when a product does not have suseProductSCCRepositories
            LOG.info("Product '{}' does not have repositories. Skipping.", root);
            return null;
        }
        return template;
    }

    /**
     * Special Handling for OES.
     * We expect that all OES products are accessible with the same subscription identified
     * by the product class aka channel family.
     *
     * This means we check accessibility of just one OES URL and enable/disable all
     * OES products depending on that result.
     *
     * @param c credential to use for the check
     * @param mirrorUrl optional mirror url
     * @param oesRepos cached list of OES Repositories or NULL
     * @return list of available repository ids
     */
    public List<Long> refreshOESRepositoryAuth(SCCCredentials c, String mirrorUrl, List<SCCRepository> oesRepos) {
        List<Long> oesRepoIds = new LinkedList<>();
        //TODO: separate OES Credentials
        if (!(c == null || accessibleUrl(OES_URL, c.getUsername(), c.getPassword()))) {
            return oesRepoIds;
        }
        for (SCCRepository repo : oesRepos) {
            Set<SCCRepositoryAuth> allAuths = repo.getRepositoryAuth();
            Set<SCCRepositoryAuth> authsThisCred = allAuths.stream()
                    .filter(a -> {
                        if (c == null) {
                            return a.getOptionalCredentials().isEmpty();
                        }
                        else {
                            return a.getOptionalCredentials().filter(oc -> oc.equals(c)).isPresent();
                        }
                    })
                    .collect(Collectors.toSet());
            if (authsThisCred.size() > 1) {
                LOG.error("More than 1 authentication found for one credential - removing all");
                authsThisCred.forEach(a -> {
                    allAuths.remove(a);
                    authsThisCred.remove(a);
                    repo.setRepositoryAuth(allAuths);
                    SCCCachingFactory.deleteRepositoryAuth(a);
                });
            }
            SCCRepositoryAuth newAuth = new SCCRepositoryBasicAuth();
            if (c == null) {
                // we need to check every repo if it is available
                String url = MgrSyncUtils.urlToFSPath(repo.getUrl(), repo.getName()).toString();
                try {
                    if (!accessibleUrl(buildRepoFileUrls(url, repo))) {
                        continue;
                    }
                }
                catch (URISyntaxException e) {
                    LOG.error("Failed to parse URL", e);
                    continue;
                }
                newAuth = new SCCRepositoryNoAuth();
            }
            // this repo exists and is accessible
            oesRepoIds.add(repo.getSccId());
            if (authsThisCred.isEmpty()) {
                // We need to create a new auth for this repo
                newAuth.setCredentials(c);
                newAuth.setRepo(repo);
                allAuths.add(newAuth);
                repo.setRepositoryAuth(allAuths);
                SCCCachingFactory.saveRepositoryAuth(newAuth);
            }
            else {
                // else: Auth exists - check, if URL still match
                SCCRepositoryAuth exAuth = authsThisCred.iterator().next();
                ContentSource updateCS = exAuth.getContentSource();
                if (updateCS != null) {
                    updateCS.setMetadataSigned(repo.isSigned());
                    updateCS.setSourceUrl(contentSourceUrlOverwrite(repo, exAuth.getUrl(), mirrorUrl));
                    ChannelFactory.save(updateCS);
                }
            }
        }
        return oesRepoIds;
    }

    /**
     * Check for configured overwrite scenarios for the provides repo URL.
     * Check if "fromdir" configuration is in place or a mirror is configured.
     * Return the correct path/url if this is the case.
     *
     * If mirror url is not NULL or "mirror" is configured via configuration file,
     * it check if the requested repository is available on that mirror.
     * In case it is, it returns the URL to the mirror.
     *
     * In case nothing special is configured, return defaultUrl
     *
     * @param repo {@link SCCRepository}
     * @param defaultUrl URL which will be returns if no special condition match
     * @param mirrorUrl optional mirror to check
     * @return URL to use for the provided repo
     */
    public String contentSourceUrlOverwrite(SCCRepository repo, String defaultUrl, String mirrorUrl) {
        String url = repo.getUrl();
        if (StringUtils.isBlank(url)) {
            return defaultUrl;
        }
        // if fromdir is set, defaultURL contains already correct file URL
        if (Config.get().getString(ContentSyncManager.RESOURCE_PATH, null) != null) {
            return defaultUrl;
        }

        // check if a mirror url is specified
        if (StringUtils.isBlank(mirrorUrl)) {
            mirrorUrl = Config.get().getString(MIRROR_CFG_KEY);
            if (StringUtils.isBlank(mirrorUrl)) {
                return defaultUrl;
            }
        }

        try {
            URI mirrorUri = new URI(mirrorUrl);
            URI sourceUri = new URI(url);

            // Setup the path
            String mirrorPath = StringUtils.defaultString(mirrorUri.getRawPath());
            String combinedPath = new File(StringUtils.stripToEmpty(mirrorPath),
                    sourceUri.getRawPath()).getPath();

            // Build full URL to test
            URI testUri = new URI(mirrorUri.getScheme(), mirrorUri.getUserInfo(), mirrorUri.getHost(),
                    mirrorUri.getPort(), combinedPath, mirrorUri.getQuery(), null);

            if (accessibleUrl(buildRepoFileUrls(testUri.toString(), repo))) {
                return testUri.toString();
            }
        }
        catch (URISyntaxException e) {
            LOG.warn(e.getMessage());
        }
        return defaultUrl;
    }

    /**
     * Build a list of URLs pointing to a file to test availablity of a repository.
     * Support either repomd or Debian style repos.
     * The first accessible defines that the repo exists and is valid
     *
     * @param url the repo url
     * @param repo the repo object
     * @return List of full URLs pointing to a file which should be available depending on the repo type
     * @throws URISyntaxException in case of an error
     */
    public List<String> buildRepoFileUrls(String url, SCCRepository repo) throws URISyntaxException {
        URI uri = new URI(url);
        List<String> relFiles = new LinkedList<>();
        List<String> urls = new LinkedList<>();

        // Debian repo
        if (repo.getDistroTarget() != null && (List.of("amd64", "arm64").contains(repo.getDistroTarget()))) {
            // There is not only 1 file we can test.
            // https://wiki.debian.org/DebianRepository/Format
            relFiles.add("Packages.xz");
            relFiles.add("Release");
            relFiles.add("Packages.gz");
            relFiles.add("Packages");
            relFiles.add("InRelease");
        }
        else {
            relFiles.add("/repodata/repomd.xml");
        }
        for (String relFile : relFiles) {
            Path urlPath = new File(Objects.toString(uri.getRawPath(), "/"), relFile).toPath();
            urls.add(new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), urlPath.toString(),
                    uri.getQuery(), null).toString());
        }
        // In case url is a mirrorlist test the plain URL as well
        if (Optional.ofNullable(uri.getQuery()).filter(q -> q.contains("=")).isPresent() ||
                url.contains("mirror.list")) {
            urls.add(url);
        }
        return urls;
    }

    /**
     * Refresh the subscription cache by reading subscriptions from SCC for all available
     * mirror credentials, consolidating and inserting into the database.
     *
     * @param subscriptions list of scc subscriptions
     * @param source source of subscriptions
     * @throws ContentSyncException in case of an error
     */
    public void refreshSubscriptionCache(List<SCCSubscriptionJson> subscriptions, ContentSyncSource source) {
        RemoteCredentials c = source.getCredentials().orElse(null);
        List<Long> cachedSccIDs = SCCCachingFactory.listSubscriptionsIdsByCredentials(c);
        Map<Long, SCCSubscription> subscriptionsBySccId = SCCCachingFactory.lookupSubscriptions()
                .stream().collect(Collectors.toMap(SCCSubscription::getSccId, s -> s));
        Map<Long, SUSEProduct> productsBySccId = SUSEProductFactory.productsByProductIds();
        for (SCCSubscriptionJson s : subscriptions) {
            SCCSubscription ns = SCCCachingFactory.saveJsonSubscription(s, c, productsBySccId, subscriptionsBySccId);
            subscriptionsBySccId.put(ns.getSccId(), ns);
            cachedSccIDs.remove(s.getId());
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found {} subscriptions with credentials: {}", subscriptions.size(), c);
        }
        for (Long subId : cachedSccIDs) {
            LOG.debug("Delete Subscription with sccId: {}", subId);
            SCCCachingFactory.deleteSubscriptionBySccId(subId);
        }
    }

    /**
     * Get subscriptions from SCC for a single pair of mirror credentials
     * and update the DB.
     * Additionally order items are fetched and put into the DB.
     * @param source the source from where to get the subscriptions
     * @return list of subscriptions as received from SCC.
     * @throws ContentSyncException in case of an error
     */
    public List<SCCSubscriptionJson> updateSubscriptions(ContentSyncSource source) throws ContentSyncException {
        if (source instanceof RMTContentSyncSource) {
            return Collections.emptyList();
        }

        try {
            SCCClient scc = this.getSCCClient(source);
            var subscriptions = scc.listSubscriptions();
            refreshSubscriptionCache(subscriptions, source);
            refreshOrderItemCache(source);
            generateOEMOrderItems(subscriptions, source);
            return subscriptions;
        }
        catch (SCCClientException e) {
            // test for OES credentials
            return handleOESCredentials(source, e, Collections::emptyList);
        }
        catch (ContentSyncSourceException e) {
            LOG.error("Unable to build client from ContentSyncSource", e);
            return Collections.emptyList();
        }
    }

    /**
     * Returns all subscriptions available to all configured credentials.
     * Update the DB with new fetched subscriptions and Order Items
     * @return list of all available subscriptions
     * @throws ContentSyncException in case of an error
     */
    public Collection<SCCSubscriptionJson> updateSubscriptions() throws ContentSyncException {
        return TimeUtils.logTime(LOG, "updateSubscriptions", () -> {
            List<ContentSyncSource> sources = filterCredentials();
            List<SCCSubscriptionJson> subscriptions = sources.stream()
                    .flatMap(source -> updateSubscriptions(source).stream())
                    .collect(Collectors.toList());

            LOG.debug("Found {} available subscriptions.", subscriptions.size());
            return subscriptions;
        });
    }

    //Some old scc credentials are in reality OES credentials and don't work for SCC but only on the OES
    //endpoint so whenever there is an error using SCC credentials we have to check if those work for OES
    //and handle it accordingly
    private <T> T handleOESCredentials(ContentSyncSource source, SCCClientException e, Supplier<T> oesReturn)
            throws ContentSyncException {
        return source.getCredentials(SCCCredentials.class)
            .filter(scc -> accessibleUrl(OES_URL, scc.getUsername(), scc.getPassword()))
            .map(scc -> oesReturn.get())
            .orElseThrow(() -> new ContentSyncException(e));
    }

    /**
     * Fetch new Order Items from SCC for the given credentials,
     * deletes all order items stored in the database below the given credentials
     * and inserts the new ones.
     * @param source the credentials
     * @throws ContentSyncException  in case of an error
     */
    public void refreshOrderItemCache(ContentSyncSource source) throws ContentSyncException  {
        try {
            SCCClient scc = this.getSCCClient(source);
            SCCCredentials credential = source.getCredentials(SCCCredentials.class).orElse(null);
            var orders = scc.listOrders();
            List<SCCOrderItem> existingOI = SCCCachingFactory.listOrderItemsByCredentials(source);
            for (SCCOrderJson order : orders) {
                for (SCCOrderItemJson j : order.getOrderItems()) {
                    SCCOrderItem oi = SCCCachingFactory.lookupOrderItemBySccId(j.getSccId()).orElse(new SCCOrderItem());
                    oi.update(j, credential);
                    SCCCachingFactory.saveOrderItem(oi);
                    existingOI.remove(oi);
                }
            }
            existingOI.stream()
                    .filter(item -> item.getSccId() >= 0)
                    .forEach(SCCCachingFactory::deleteOrderItem);
        }
        catch (SCCClientException e) {
            // test for OES credentials
            handleOESCredentials(source, e, () -> 0);
        }
        catch (ContentSyncSourceException e) {
            LOG.error("Unable to get client from ContentSyncSource", e);
        }
    }

    /**
     * Generates OrderItems for OEM subscriptions.
     *
     * @param subscriptions the subscriptions
     * @param source scc credentials source
     */
    private void generateOEMOrderItems(List<SCCSubscriptionJson> subscriptions, ContentSyncSource source) {
        List<SCCOrderItem> existingOI = SCCCachingFactory.listOrderItemsByCredentials(source);
        subscriptions.stream()
                .filter(sub -> "oem".equals(sub.getType()))
                .forEach(sub -> {
                    if (sub.getSkus().size() == 1) {
                        LOG.debug("Generating order item for OEM subscription {}, SCC ID: {}",
                                sub.getName(), sub.getId());
                        long subscriptionSccId = sub.getId();
                        SCCOrderItem oemOrder = SCCCachingFactory.lookupOrderItemBySccId(-subscriptionSccId)
                                .orElse(new SCCOrderItem());
                        // HACK: use inverted subscription id as new the order item id
                        oemOrder.setSccId(-subscriptionSccId);
                        oemOrder.setQuantity(sub.getSystemLimit().longValue());
                        oemOrder.setCredentials(source.getCredentials().orElse(null));
                        oemOrder.setStartDate(sub.getStartsAt());
                        oemOrder.setEndDate(sub.getExpiresAt());
                        oemOrder.setSku(sub.getSkus().get(0));
                        oemOrder.setSubscriptionId(subscriptionSccId);
                        SCCCachingFactory.saveOrderItem(oemOrder);
                        existingOI.remove(oemOrder);
                    }
                    else {
                        LOG.warn("Subscription {}, SCC ID: {} does not have a single SKU. " +
                                "Not generating Order Item for it.", sub.getName(), sub.getId());
                    }
                });
        existingOI.stream()
                .filter(item -> item.getSccId() < 0)
                .forEach(SCCCachingFactory::deleteOrderItem);
    }

    /**
     * Update repositories and its available authentications.
     * If mirrorUrl is given, the method search for available repositories
     * and prefer them over the official repository urls.
     * Set to NULL if no mirror should be used.
     *
     * @param mirrorUrl optional URL string to search for available repositories
     * @throws ContentSyncException in case of an error
     */
    public void updateRepositories(String mirrorUrl) throws ContentSyncException {
        TimeUtils.logTime(LOG, "updateRepositories", () ->
                refreshRepositoriesAuthentication(mirrorUrl, false)
        );
    }

    /**
     * Update repositories and its available authentications for Payg only.
     *
     * @throws ContentSyncException in case of an error
     */
    public void updateRepositoriesPayg() throws ContentSyncException {
        TimeUtils.logTime(LOG, "updateRepositoriesPayg", () ->
                refreshRepositoriesAuthentication(null, true)
        );
    }

    /**
     * Update channel families in DB with data from the channel_families.json file.
     * @param channelFamilies List of families.
     * @throws ContentSyncException in case of an error
     */
    public void updateChannelFamilies(Collection<ChannelFamilyJson> channelFamilies) throws ContentSyncException {
        LOG.info("Sync started with updateChannelFamilies");
        List<String> suffixes = Arrays.asList("", "ALPHA", "BETA");

        for (ChannelFamilyJson channelFamily : channelFamilies) {
            for (String suffix : suffixes) {
                ChannelFamily family = createOrUpdateChannelFamily(
                        channelFamily.getLabel(), channelFamily.getName(), suffix);
                // Create rhnPublicChannelFamily entry if it doesn't exist
                if (family != null && family.getPublicChannelFamily() == null) {
                    PublicChannelFamily pcf = new PublicChannelFamily();

                    // save the public channel family
                    pcf.setChannelFamily(family);
                    ChannelFamilyFactory.save(pcf);
                    family.setPublicChannelFamily(pcf);
                }
            }
        }
    }

    /**
     * Update a product in DB
     * @param p the SCC product
     * @param product the database product whcih should be updated
     * @param channelFamilyByLabel lookup map for channel family by label
     * @param packageArchMap lookup map for package archs
     * @return the updated product
     */
    public static SUSEProduct updateProduct(SCCProductJson p, SUSEProduct product,
                                            Map<String, ChannelFamily> channelFamilyByLabel,
                                            Map<String, PackageArch> packageArchMap) {
        // it is not guaranteed for this ID to be stable in time, as it
        // depends on IBS
        product.setProductId(p.getId());
        product.setFriendlyName(p.getFriendlyName());
        product.setDescription(p.getDescription());
        product.setFree(p.isFree());
        product.setReleaseStage(p.getReleaseStage());

        product.setName(p.getIdentifier().toLowerCase());
        product.setVersion(p.getVersion() != null ? p.getVersion().toLowerCase() : null);
        product.setRelease(p.getReleaseType() != null ? p.getReleaseType().toLowerCase() : null);
        product.setBase(p.isBaseProduct());
        // Create the channel family if it is not available
        String productClass = p.getProductClass();
        product.setChannelFamily(
                !StringUtils.isBlank(productClass) ?
                        createOrUpdateChannelFamily(productClass, null, channelFamilyByLabel) : null);

        PackageArch pArch = packageArchMap.computeIfAbsent(p.getArch(), PackageFactory::lookupPackageArchByLabel);
        if (pArch == null && p.getArch() != null) {
            if (!p.getArch().equals("multi-arch")) {
                // unsupported architecture, skip the product
                LOG.error("Unknown architecture '{}'. This may be caused by a missing database migration", p.getArch());
            }
            // multi-arch is used by SCC - we do not handle these products, no need to write an error message
        }
        else {
            product.setArch(pArch);
        }

        return product;
    }

    /**
     * Create a new product in DB
     * @param p product from SCC
     * @param channelFamilyMap lookup map for channel family by label
     * @param packageArchMap lookup map for package arch by label
     * @return the new product
     */
    public static SUSEProduct createNewProduct(SCCProductJson p, Map<String, ChannelFamily> channelFamilyMap,
                                               Map<String, PackageArch> packageArchMap) {
        // Otherwise create a new SUSE product and save it
        SUSEProduct product = new SUSEProduct();

        String productClass = p.getProductClass();

        product.setProductId(p.getId());
        // Convert those to lower case to match channels.xml format
        product.setName(p.getIdentifier().toLowerCase());
        // Version rarely can be null.
        product.setVersion(p.getVersion() != null ?
                p.getVersion().toLowerCase() : null);
        // Release Type often can be null.
        product.setRelease(p.getReleaseType() != null ?
                p.getReleaseType().toLowerCase() : null);
        product.setFriendlyName(p.getFriendlyName());
        product.setDescription(p.getDescription());
        product.setFree(p.isFree());
        product.setReleaseStage(p.getReleaseStage());
        product.setBase(p.isBaseProduct());


        product.setChannelFamily(
                !StringUtils.isBlank(productClass) ?
                        channelFamilyMap.computeIfAbsent(productClass,
                                pc -> createOrUpdateChannelFamily(pc, null, channelFamilyMap)) : null);

        PackageArch pArch = packageArchMap.computeIfAbsent(p.getArch(), PackageFactory::lookupPackageArchByLabel);
        if (pArch == null && p.getArch() != null) {
            if (!p.getArch().equals("multi-arch")) {
                // unsupported architecture, skip the product
                LOG.error("Unknown architecture '{}'. This may be caused by a missing database migration", p.getArch());
            }
            // multi-arch is used by SCC - we do not handle these products, no need to write an error message
        }
        else {
            product.setArch(pArch);
        }
        return product;
    }

    private List<ProductTreeEntry> loadStaticTree() throws ContentSyncException {
        String tag = Config.get().getString(ConfigDefaults.PRODUCT_TREE_TAG);
        return loadStaticTree(tag);
    }

    /*
     * load the static tree from file
     */
    private List<ProductTreeEntry> loadStaticTree(String tag) throws ContentSyncException {
        List<ProductTreeEntry> tree = sumaProductTreeJson.map(treeJson -> {
            try {
                return JsonParser.GSON.<List<ProductTreeEntry>>fromJson(new BufferedReader(new InputStreamReader(
                                new FileInputStream(sumaProductTreeJson.get()))),
                        SCCClientUtils.toListType(ProductTreeEntry.class));
            }
            catch (IOException e) {
                LOG.error(e.getMessage(), e);
                return Collections.<ProductTreeEntry>emptyList();
            }
        }).orElseGet(() -> {
            List<ContentSyncSource> sources = filterCredentials();
            return sources.stream().map(source -> {
                try {
                    SCCClient scc = getSCCClient(source);
                    return scc.productTree();
                }
                catch (SCCClientException e) {
                    throw new ContentSyncException(e);
                }
            }).findFirst().orElseGet(Collections::emptyList);
        });

        return tree.stream().filter(e -> e.getTags().isEmpty() || e.getTags().contains(tag))
                .collect(Collectors.toList());
    }

    /**
     * Return a distinct flat list of products
     * @param products product tree
     * @return flat list of products
     */
    public static Stream<SCCProductJson> flattenProducts(List<SCCProductJson> products) {
        return products.stream().flatMap(p -> Stream.concat(
                        Stream.of(p),
                        flattenProducts(p.getExtensions())
                ))
                .distinct();
    }

    /**
     * Collect all repositories from the product list and return them as list
     * @param products the product list
     * @return a list of repositories
     */
    public static List<SCCRepositoryJson> collectRepos(List<SCCProductJson> products) {
        return products.stream().flatMap(p -> p.getRepositories().stream()).collect(Collectors.toList());
    }

    private static <T> Map<Long, T> productAttributeOverride(List<ProductTreeEntry> tree,
                                                             Function<ProductTreeEntry, T> attrGetter) {
        return tree.stream()
                .collect(Collectors.groupingBy(
                        ProductTreeEntry::getProductId, Collectors.mapping(
                                attrGetter, Collectors.toSet())))
                .entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> {
                    if (e.getValue().size() != 1) {
                        throw new RuntimeException(
                                "found more than 1 unique value for a product attribute override: " +
                                        "id " + e.getKey() +
                                        " values " + e.getValue().stream()
                                        .map(Object::toString)
                                        .collect(Collectors.joining(","))
                        );
                    }
                    else {
                        return e.getValue().iterator().next();
                    }
                })).entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private List<SCCProductJson> overrideProductAttributes(
            List<SCCProductJson> jsonProducts, List<ProductTreeEntry> tree) {
        Map<Long, Optional<ProductType>> productTypeById = productAttributeOverride(
                tree, ProductTreeEntry::getProductType);

        Map<Long, ReleaseStage> releaseStageById = productAttributeOverride(
                tree, ProductTreeEntry::getReleaseStage);

        Optional<IssHub> optIssHub = hubFactory.lookupIssHub();
        String hubFqdn = optIssHub.map(IssHub::getFqdn).orElse("invalid.hub.internal");

        return jsonProducts.stream().map(product -> {
            ProductType productType = Optional.ofNullable(productTypeById.get(product.getId()))
                    .flatMap(Function.identity())
                    .orElseGet(product::getProductType);

            ReleaseStage releaseStage = Optional.ofNullable(releaseStageById.get(product.getId()))
                    .orElseGet(product::getReleaseStage);
            if (optIssHub.isPresent()) {
                product.getRepositories().forEach(r ->
                        r.setUrl("https://%1$s/rhn/manager/download/hubsync/%2$d/".formatted(hubFqdn, r.getSCCId())));
            }
            return product.copy()
                    .setProductType(productType)
                    .setReleaseStage(releaseStage)
                    .build();
        }).collect(Collectors.toList());
    }


    /**
     * Update Products, Repositories and relationship table in DB.
     * @param productsById map of scc products by id
     * @param reposById map of scc repositories by id
     * @param tree the static suse product tree
     */
    public void updateProducts(Map<Long, SCCProductJson> productsById, Map<Long, SCCRepositoryJson> reposById,
                                      List<ProductTreeEntry> tree) {
        Map<String, PackageArch> packageArchMap = PackageFactory.lookupPackageArch()
                .stream().collect(Collectors.toMap(PackageArch::getLabel, a -> a));
        Map<String, ChannelFamily> channelFamilyMap = ChannelFamilyFactory.getAllChannelFamilies()
                .stream().collect(Collectors.toMap(ChannelFamily::getLabel, cf -> cf));
        Map<Tuple3<Long, Long, Long>, ChannelTemplate> dbChannelTemplatesByIds =
                SUSEProductFactory.allChannelTemplatesByIds();
        Map<Long, SUSEProduct> dbProductsById = SUSEProductFactory.findAllSUSEProducts().stream()
                .collect(Collectors.toMap(SUSEProduct::getProductId, p -> p));
        Map<Long, SCCRepository> dbReposById = SCCCachingFactory.lookupRepositories().stream()
                .collect(Collectors.toMap(SCCRepository::getSccId, r -> r));
        Map<Tuple3<Long, Long, Long>, SUSEProductExtension> dbSUSEProductExtensionsByIds = SUSEProductFactory
                .findAllSUSEProductExtensions().stream().collect(Collectors.toMap(
                        e -> new Tuple3<>(
                                e.getBaseProduct().getProductId(),
                                e.getExtensionProduct().getProductId(),
                                e.getRootProduct().getProductId()),
                        e -> e
                ));
        Set<Long> productIdsSwitchedToReleased = new HashSet<>();

        Map<Long, SUSEProduct> productMap = productsById.values().stream().map(productJson -> {

            // If the product is release the id should be stable
            // so we don't do the fuzzy matching to reduce unexpected behaviour
            if (productJson.getReleaseStage() == ReleaseStage.released) {
                return Opt.fold(Optional.ofNullable(dbProductsById.get(productJson.getId())),
                        () -> {
                            SUSEProduct prod = createNewProduct(productJson, channelFamilyMap, packageArchMap);
                            dbProductsById.put(prod.getProductId(), prod);
                            return prod;
                        },
                        prod -> {
                            if (prod.getReleaseStage() != ReleaseStage.released) {
                                // product switched from beta to released.
                                // tag for later cleanup all assosicated repositories
                                productIdsSwitchedToReleased.add(prod.getProductId());
                            }
                            updateProduct(productJson, prod, channelFamilyMap, packageArchMap);
                            dbProductsById.put(prod.getProductId(), prod);
                            return prod;
                        }
                );
            }
            else {
                return Opt.fold(
                        Opt.or(
                                Optional.ofNullable(dbProductsById.get(productJson.getId())),
                                Optional.ofNullable(SUSEProductFactory.findSUSEProduct(
                                        productJson.getIdentifier(), productJson.getVersion(),
                                        productJson.getReleaseType(), productJson.getArch(), false))
                        ),
                        () -> {
                            SUSEProduct prod = createNewProduct(productJson, channelFamilyMap, packageArchMap);
                            dbProductsById.put(prod.getProductId(), prod);
                            return prod;
                        },
                        prod -> {
                            updateProduct(productJson, prod, channelFamilyMap, packageArchMap);
                            dbProductsById.put(prod.getProductId(), prod);
                            return prod;
                        }
                );
            }
        }).collect(Collectors.toMap(SUSEProduct::getProductId, p -> p));


        Map<Long, SCCRepository> repoMap = reposById.values().stream()
                .map(repoJson -> Opt.fold(Optional.ofNullable(dbReposById.get(repoJson.getSCCId())),
                        () -> {
                            SCCRepository r = new SCCRepository();
                            r.update(repoJson);
                            dbReposById.put(r.getSccId(), r);
                            return r;
                        },
                        r -> {
                            r.setName(repoJson.getName());
                            r.setDescription(repoJson.getDescription());
                            r.setUrl(repoJson.getUrl());
                            r.setInstallerUpdates(repoJson.isInstallerUpdates());
                            dbReposById.put(r.getSccId(), r);
                            return r;
                        })).collect(Collectors.toMap(SCCRepository::getSccId, p -> p));

        Map<Tuple3<Long, Long, Long>, ChannelTemplate> channelTemplatesToSave = new HashMap<>();
        Map<Tuple3<Long, Long, Long>, SUSEProductExtension> extensionsToSave = new HashMap<>();
        Set<String> channelsToCleanup = new HashSet<>();

        tree.forEach(entry -> {
            SCCProductJson productJson = productsById.get(entry.getProductId());

            SCCRepositoryJson repoJson = reposById.get(entry.getRepositoryId());

            SCCProductJson rootJson = productsById.get(entry.getRootProductId());

            Optional<Optional<SCCProductJson>> parentJson = entry.getParentProductId()
                    .map(id -> Optional.ofNullable(productsById.get(id)));

            if (productJson != null  && repoJson != null && rootJson != null &&
                    (parentJson.isEmpty() || parentJson.get().isPresent())) {

                Tuple3<Long, Long, Long> ids = new Tuple3<>(rootJson.getId(), productJson.getId(), repoJson.getSCCId());
                SUSEProduct product = productMap.get(productJson.getId());
                SUSEProduct root = productMap.get(rootJson.getId());
                //FIXME: this is not pretty and should be changed if somebody has the time
                Optional<SUSEProduct> parent = parentJson.flatMap(Function.identity())
                        .map(p -> productMap.get(p.getId()));

                ChannelTemplate template = Opt.fold(Optional.ofNullable(dbChannelTemplatesByIds.get(ids)),
                        () -> {
                            SCCRepository repo = repoMap.get(repoJson.getSCCId());
                            repo.setSigned(isRepoSigned(entry.isSigned()));

                            ChannelTemplate channelTemplate = new ChannelTemplate();
                            channelTemplate.setUpdateTag(entry.getUpdateTag().orElse(null));
                            channelTemplate.setChannelLabel(entry.getChannelLabel());
                            channelTemplate.setParentChannelLabel(entry.getParentChannelLabel().orElse(null));
                            channelTemplate.setChannelName(entry.getChannelName());
                            channelTemplate.setMandatory(entry.isMandatory());
                            channelTemplate.setProduct(product);
                            channelTemplate.setRepository(repo);
                            channelTemplate.setRootProduct(root);
                            if (!entry.getGpgInfo().isEmpty()) {
                                channelTemplate.setGpgKeyUrl(entry.getGpgInfo()
                                        .stream().map(GpgInfoEntry::getUrl).collect(Collectors.joining(" ")));
                                // we use only the 1st entry for id and fingerprint
                                channelTemplate.setGpgKeyId(entry.getGpgInfo().get(0).getKeyId());
                                channelTemplate.setGpgKeyFingerprint(entry.getGpgInfo().get(0).getFingerprint());
                            }
                            dbChannelTemplatesByIds.put(ids, channelTemplate);

                            if (productIdsSwitchedToReleased.contains(entry.getProductId())) {
                                channelsToCleanup.add(entry.getChannelLabel());
                            }
                            repo.addChannelTemplate(channelTemplate);
                            return channelTemplate;
                        }, channelTemplate -> {
                            if (entry.getReleaseStage() != ReleaseStage.released) {
                                // Only allowed to change in Alpha or Beta stage
                                channelTemplate.setUpdateTag(entry.getUpdateTag().orElse(null));
                                channelTemplate.setChannelLabel(entry.getChannelLabel());
                                channelTemplate.setParentChannelLabel(entry.getParentChannelLabel().orElse(null));
                            }
                            else {
                                if (!entry.getParentChannelLabel()
                                        .equals(Optional.ofNullable(channelTemplate.getParentChannelLabel()))) {
                                    LOG.error("parent_channel_label changed from '{}' to '{}' but its not allowed " +
                                                    "to change.", channelTemplate.getParentChannelLabel(),
                                            entry.getParentChannelLabel());
                                }

                                if (!entry.getUpdateTag()
                                        .equals(Optional.ofNullable(channelTemplate.getUpdateTag()))) {
                                    LOG.debug("updatetag changed from '{}' to '{}' but its not allowed to change.",
                                            channelTemplate.getUpdateTag(), entry.getUpdateTag());
                                }

                                if (!entry.getChannelLabel().equals(channelTemplate.getChannelLabel())) {
                                    LOG.error("channel_label changed from '{}' to '{}' but its not allowed to change.",
                                            channelTemplate.getChannelLabel(), entry.getChannelLabel());
                                }
                            }
                            // Allowed to change also in released stage
                            channelTemplate.setChannelName(entry.getChannelName());
                            channelTemplate.setMandatory(entry.isMandatory());
                            channelTemplate.getRepository().setSigned(isRepoSigned(entry.isSigned()));
                            if (!entry.getGpgInfo().isEmpty()) {
                                channelTemplate.setGpgKeyUrl(entry.getGpgInfo()
                                        .stream().map(GpgInfoEntry::getUrl).collect(Collectors.joining(" ")));
                                // we use only the 1st entry for id and fingerprint
                                channelTemplate.setGpgKeyId(entry.getGpgInfo().get(0).getKeyId());
                                channelTemplate.setGpgKeyFingerprint(entry.getGpgInfo().get(0).getFingerprint());
                            }
                            else {
                                channelTemplate.setGpgKeyUrl(null);
                                channelTemplate.setGpgKeyId(null);
                                channelTemplate.setGpgKeyFingerprint(null);
                            }

                            if (productIdsSwitchedToReleased.contains(entry.getProductId())) {
                                channelsToCleanup.add(entry.getChannelLabel());
                            }
                            return channelTemplate;
                        });

                parent.ifPresent(p -> {
                    Tuple3<Long, Long, Long> peId = new Tuple3<>(
                            p.getProductId(), product.getProductId(), root.getProductId());

                    SUSEProductExtension pe = Opt.fold(Optional.ofNullable(dbSUSEProductExtensionsByIds.get(peId)),
                            () -> new SUSEProductExtension(p, product, root, entry.isRecommended()),
                            existingPe -> {
                                existingPe.setRecommended(entry.isRecommended());
                                return existingPe;
                            }
                    );
                    extensionsToSave.put(peId, pe);
                });

                channelTemplatesToSave.put(ids, template);
            }
        });


        dbSUSEProductExtensionsByIds.entrySet().stream()
                .filter(e -> !extensionsToSave.containsKey(e.getKey()))
                .map(Map.Entry::getValue)
                .forEach(SUSEProductFactory::remove);


        dbChannelTemplatesByIds.entrySet().stream()
                .filter(e -> !channelTemplatesToSave.containsKey(e.getKey()))
                .map(Map.Entry::getValue)
                .forEach(SUSEProductFactory::remove);

        dbReposById.entrySet().stream()
                .filter(e -> !repoMap.containsKey(e.getKey()))
                .map(Map.Entry::getValue)
                .forEach(r -> {
                    r.getRepositoryAuth().forEach(SCCCachingFactory::deleteRepositoryAuth);
                    SCCCachingFactory.deleteRepository(r);
                });

        productMap.values().forEach(SUSEProductFactory::save);
        extensionsToSave.values().forEach(SUSEProductFactory::save);
        repoMap.values().forEach(SUSEProductFactory::save);
        channelTemplatesToSave.values().forEach(SUSEProductFactory::save);

        ChannelFactory.listVendorChannels().forEach(c -> {
            updateChannel(c);
            if (channelsToCleanup.contains(c.getLabel())) {
                ChannelManager.disassociateChannelEntries(c);
            }
        });
    }

    /**
     * Update SUSE Products from SCC.
     * @param products the scc products
     * @throws ContentSyncException in case of an error
     */
    public void updateSUSEProducts(List<SCCProductJson> products) throws ContentSyncException {
        TimeUtils.logTime(LOG, "updateSUSEProducts", () ->
                updateSUSEProducts(
                        Stream.concat(
                                products.stream(),
                                getAdditionalProducts().stream()
                        ).collect(Collectors.toList()),
                        loadStaticTree(), getAdditionalRepositories())
        );
    }

    /**
     * Creates or updates entries in the SUSEProducts database table with a given list of
     * {@link SCCProductJson} objects.
     *
     * @param products        list of products
     * @param staticTree      suse product tree with fixes and additional data
     * @param additionalRepos list of additional static repos
     */
    public void updateSUSEProducts(List<SCCProductJson> products, List<ProductTreeEntry> staticTree,
                                   List<SCCRepositoryJson> additionalRepos) {
        Map<Long, SUSEProduct> processed = new HashMap<>();

        List<SCCProductJson> allProducts = overrideProductAttributes(
                flattenProducts(products).collect(Collectors.toList()),
                staticTree
        );

        Map<Long, SCCProductJson> productsById = allProducts.stream().collect(Collectors.toMap(
                SCCProductJson::getId,
                Function.identity(),
                (x, y) -> x
        ));

        Map<Long, SCCRepositoryJson> reposById = Stream.concat(
                collectRepos(allProducts).stream(),
                additionalRepos.stream()
        ).collect(Collectors.toMap(
                SCCRepositoryJson::getSCCId,
                Function.identity(),
                (x, y) -> x
        ));

        updateProducts(productsById, reposById, staticTree);

        SUSEProductFactory.removeAllExcept(processed.values());

        updateUpgradePaths(products);
        HibernateFactory.getSession().flush();
    }

    /**
     * Check if the product has any repositories and all the mandatory ones for the given root are accessible.
     * No recursive checking if bases are accessible too.
     * For ISS Slave we cannot check if the channel would be available on the master.
     * In this case we also return true
     * @param product the product to check
     * @param root the root we check for
     * @return true in case of all mandatory repos could be mirrored, otherwise false
     */
    public boolean isProductAvailable(SUSEProduct product, SUSEProduct root) {
        Set<ChannelTemplate> templates = product.getChannelTemplates();
        if (templates == null) {
            return false;
        }
        return !templates.isEmpty() && templates.stream()
                .filter(e -> e.getRootProduct().equals(root))
                .filter(ChannelTemplate::isMandatory)
                .allMatch(this::isChannelAccessible);
    }

    private boolean isChannelAccessible(ChannelTemplate template) {
        boolean isPublic = template.getProduct().getChannelFamily().isPublic();
        boolean isAvailable = ChannelFactory.lookupByLabel(template.getChannelLabel()) != null;
        boolean isISSSlave = IssFactory.getCurrentMaster() != null || isPeripheral;
        boolean isMirrorable = false;
        if (!isISSSlave) {
            isMirrorable = template.getRepository().isAccessible();
        }
        LOG.debug("{} - {} isPublic: {} isMirrorable: {} isISSSlave: {} isAvailable: {}",
                template.getProduct().getFriendlyName(),
                template.getChannelLabel(), isPublic, isMirrorable, isISSSlave, isAvailable);
        return  isPublic && (isMirrorable || isISSSlave || isAvailable);
    }

    /**
     * Find all available repositories for product and all extensions of product
     * @param root root product of product
     * @param product product to get available repositories from
     * @return stream of available repositories of product
     */
    private Stream<ChannelTemplate> getAvailableChannels(SUSEProduct root, SUSEProduct product) {
        List<ChannelTemplate> allEntries = SUSEProductFactory.allChannelTemplates();
        List<Long> repoIdsWithAuth = SCCCachingFactory.lookupRepositoryIdsWithAuth();
        Map<Tuple2<SUSEProduct, SUSEProduct>, List<SUSEProductExtension>> allSUSEProdExt =
                SUSEProductFactory.findAllSUSEProductExtensions().stream()
                        .collect(Collectors.groupingBy(e -> new Tuple2<>(e.getRootProduct(), e.getBaseProduct())));

        Map<Tuple2<SUSEProduct, SUSEProduct>, List<ChannelTemplate>> entriesByProducts = allEntries.stream()
                .collect(Collectors.groupingBy(e -> new Tuple2<>(e.getRootProduct(), e.getProduct())));
        return getAvailableChannels(root, product, entriesByProducts, repoIdsWithAuth, allSUSEProdExt);
    }

    /**
     * Find all available repositories for product and all extensions of product
     * @param root root product of product
     * @param product product to get available repositories from
     * @param allEntries lookup map for repositories by product and root product
     * @param repoIdsWithAuth lookup list for all authenticated repositories by id
     * @param allSUSEProdExt lookup map for all extensions
     * @return stream of available repositories of product
     */
    private Stream<ChannelTemplate> getAvailableChannels(
        SUSEProduct root,
        SUSEProduct product,
        Map<Tuple2<SUSEProduct, SUSEProduct>, List<ChannelTemplate>> allEntries,
        List<Long> repoIdsWithAuth,
        Map<Tuple2<SUSEProduct, SUSEProduct>, List<SUSEProductExtension>> allSUSEProdExt
    ) {
        Tuple2<SUSEProduct, SUSEProduct> rootProductTuple = new Tuple2<>(root, product);
        List<ChannelTemplate> entries =
                allEntries.getOrDefault(rootProductTuple, Collections.emptyList());
        boolean isAccessible = entries.stream()
                .filter(ChannelTemplate::isMandatory)
                .allMatch(entry -> {
                    boolean isPublic = entry.getProduct().getChannelFamily().isPublic();
                    boolean hasAuth = repoIdsWithAuth.contains(entry.getRepository().getId());
                    LOG.debug("{} - {} isPublic: {} hasAuth: {}", product.getFriendlyName(),
                            entry.getChannelLabel(), isPublic, hasAuth);
                    return  isPublic &&
                            // isMirrorable
                            hasAuth;
                });

            if (LOG.isDebugEnabled()) {
                LOG.debug("{}: {} {}", product.getFriendlyName(), isAccessible, entries.stream()
                        .map(ChannelTemplate::getChannelLabel)
                        .collect(Collectors.joining(",")));
            }

        if (isAccessible) {
            return Stream.concat(
                    entries.stream().filter(e ->
                            e.isMandatory() || repoIdsWithAuth.contains(e.getRepository().getId())
                    ),
                    // We iterate recursively to not evaluate extensions when the parent is not accessible
                    allSUSEProdExt.getOrDefault(rootProductTuple, new ArrayList<>())
                            .stream()
                            .map(SUSEProductExtension::getExtensionProduct)
                            .flatMap(nextProduct -> getAvailableChannels(root, nextProduct, allEntries,
                                    repoIdsWithAuth, allSUSEProdExt))
            );
        }
        else {
            return Stream.empty();
        }
    }

    /**
     * Get a list of all actually available channels based on available channel families
     * as well as some other criteria.
     * @return list of available channels
     */
    public List<ChannelTemplate> getAvailableChannels() {
        List<ChannelTemplate> allEntries = SUSEProductFactory.allChannelTemplates();
        List<Long> repoIdsWithAuth = SCCCachingFactory.lookupRepositoryIdsWithAuth();
        Map<Tuple2<SUSEProduct, SUSEProduct>, List<SUSEProductExtension>> allSUSEProdExt =
                SUSEProductFactory.findAllSUSEProductExtensions().stream()
                        .collect(Collectors.groupingBy(e -> new Tuple2<>(e.getRootProduct(), e.getBaseProduct())));

        Map<Tuple2<SUSEProduct, SUSEProduct>, List<ChannelTemplate>> entriesByProducts = allEntries.stream()
                .collect(Collectors.groupingBy(e -> new Tuple2<>(e.getRootProduct(), e.getProduct())));

        return allEntries.stream()
                .filter(ChannelTemplate::isRoot)
                .map(ChannelTemplate::getProduct)
                .distinct()
                .flatMap(p -> getAvailableChannels(p, p, entriesByProducts, repoIdsWithAuth, allSUSEProdExt))
                .collect(Collectors.toList());
    }

    /**
     * Recreate contents of the suseUpgradePaths table predecessor_ids from SCC
     *
     * @param products Collection of SCC Products
     */
    public void updateUpgradePaths(Collection<SCCProductJson> products) {
        List<SUSEProduct> allSUSEProducts = SUSEProductFactory.findAllSUSEProducts();
        Map<Long, SUSEProduct> productsById = allSUSEProducts
                .stream().collect(Collectors.toMap(SUSEProduct::getProductId, p -> p));

        Map<String, SCCProductJson> sles = new HashMap<>();
        Map<String, SCCProductJson> sap = new HashMap<>();
        products.stream()
                .filter(SCCProductJson::isBaseProduct)
                .filter(p -> p.getCpe() != null &&
                        (p.getCpe().startsWith("cpe:/o:suse:sles:15:") ||
                                p.getCpe().startsWith("cpe:/o:suse:sles_sap:15:")))
                .forEach(p -> {
                    String ident = String.format("%s-%s", p.getVersion(), p.getArch());
                    if (p.getCpe().startsWith("cpe:/o:suse:sles:15:")) {
                        sles.put(ident, p);
                    }
                    else {
                        sap.put(ident, p);
                    }
                });
        Set<Tuple2<Long, Long>> sles2sap = new HashSet<>();
        sles.forEach((k, v) -> {
            if (sap.containsKey(k)) {
                sles2sap.add(new Tuple2<>(v.getId(), sap.get(k).getId()));
            }
        });

        Map<Long, Set<Long>> newPaths = Stream.concat(
                Stream.concat(staticUpgradePaths(), sles2sap.stream()),
                        products.stream()
                                .flatMap(p -> p.getOnlinePredecessorIds()
                                        .stream()
                                        .map(pre -> new Tuple2<>(pre, p.getId()))
                                )
                )
                .collect(Collectors.groupingBy(Tuple2::getA, Collectors.mapping(Tuple2::getB, Collectors.toSet())));

        allSUSEProducts.forEach(p -> {
            Set<SUSEProduct> successors = newPaths.getOrDefault(p.getProductId(), Collections.emptySet()).stream()
                    .flatMap(sId -> Opt.stream(Optional.ofNullable(productsById.get(sId))))
                    .collect(Collectors.toSet());
            Set<SUSEProduct> existingSuccessors = p.getUpgrades();
            existingSuccessors.retainAll(successors);
            existingSuccessors.addAll(successors);
            SUSEProductFactory.save(p);
        });
    }

    /**
     * Return the list of available channels with their status.
     *
     * @return list of channels
     */
    public List<MgrSyncChannelDto> listChannels() {

        return listProducts().stream().flatMap(p -> Stream.concat(
                p.getChannels().stream(),
                p.getExtensions().stream().flatMap(e -> e.getChannels().stream())
        )).collect(Collectors.toList());
    }

    protected Optional<String> getTokenFromURL(String url) {
        Optional<String> token = Optional.empty();
        try {
            URI uri = new URI(url);
            token = Arrays.stream(Optional.ofNullable(uri.getQuery()).orElse("").split("&"))
                    .filter(p -> !p.isEmpty())
                    .filter(MgrSyncUtils::isAuthToken)
                    .findFirst();
        }
        catch (URISyntaxException e) {
            LOG.warn("Unable to parse URL: {}", url);
        }
        return token;
    }

    /**
     * Update Channel database object with new data from SCC.
     * @param dbChannel channel to update
     */
    public static void updateChannel(Channel dbChannel) {
        if (dbChannel == null) {
            LOG.error("Channel does not exist");
            return;
        }
        String label = dbChannel.getLabel();
        List<ChannelTemplate> channelTemplates = SUSEProductFactory.lookupChannelTemplateByChannelLabel(label);
        boolean regenPillar = false;

        Optional<ChannelTemplate> chanTmplOpt = channelTemplates.stream().findFirst();
        if (chanTmplOpt.isEmpty()) {
            LOG.warn("Expired Vendor Channel with label '{}' found. To remove it please run: ", label);
            LOG.warn("spacewalk-remove-channel -c {}", label);
        }
        else {
            ChannelTemplate chanTmpl = chanTmplOpt.get();
            SUSEProduct product = chanTmpl.getProduct();

            // update only the fields which are save to be updated
            dbChannel.setChannelFamily(product.getChannelFamily());
            dbChannel.setName(chanTmpl.getChannelName());
            dbChannel.setSummary(product.getFriendlyName());
            dbChannel.setDescription(
                    Optional.ofNullable(product.getDescription())
                            .orElse(product.getFriendlyName()));
            dbChannel.setProduct(MgrSyncUtils.findOrCreateChannelProduct(product));
            dbChannel.setProductName(MgrSyncUtils.findOrCreateProductName(product.getName()));
            dbChannel.setUpdateTag(chanTmpl.getUpdateTag());
            dbChannel.setInstallerUpdates(chanTmpl.getRepository().isInstallerUpdates());
            if (!Objects.equals(dbChannel.getGPGKeyUrl(), chanTmpl.getGpgKeyUrl())) {
                dbChannel.setGPGKeyUrl(chanTmpl.getGpgKeyUrl());
                regenPillar = true;
            }
            dbChannel.setGPGKeyId(chanTmpl.getGpgKeyId());
            dbChannel.setGPGKeyFp(chanTmpl.getGpgKeyFingerprint());
            ChannelFactory.save(dbChannel);

            // update Mandatory Flag
            for (SUSEProductChannel pc : dbChannel.getSuseProductChannels()) {
                for (ChannelTemplate ct : channelTemplates) {
                    if (ct.getProduct().equals(pc.getProduct()) && ct.isMandatory() != pc.isMandatory()) {
                        pc.setMandatory(ct.isMandatory());
                        regenPillar = true;
                        SUSEProductFactory.save(pc);
                    }
                }
            }
        }
        if (regenPillar) {
            for (MinionServer minion : ServerFactory.listMinionsByChannel(dbChannel.getId())) {
                MinionGeneralPillarGenerator gen = new MinionGeneralPillarGenerator();
                gen.generatePillarData(minion);
            }
        }
    }

    /**
     * Add a new channel to the database.
     * @param label the label of the channel to be added.
     * @param mirrorUrl repo mirror passed by cli
     * @throws ContentSyncException in case of problems
     */
    public void addChannel(String label, String mirrorUrl) throws ContentSyncException {
        // Return immediately if the channel is already there
        if (ChannelFactory.doesChannelLabelExist(label)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Channel exists ({}), returning...", label);
            }
            return;
        }
        List<ChannelTemplate> channelTemplates = SUSEProductFactory.lookupChannelTemplateByChannelLabel(label);
        List<SUSEProduct> products = channelTemplates.stream()
                .map(ChannelTemplate::getProduct).toList();
        Opt.consume(channelTemplates.stream().findFirst(),
                () -> {
                    throw new ContentSyncException("No product tree entry found for label: '" + label + "'");
                },
                chanTmpl -> {
                    SUSEProduct product = chanTmpl.getProduct();

                    if (getAvailableChannels(chanTmpl.getRootProduct(), product)
                            .noneMatch(e -> e.getChannelLabel().equals(label))) {
                        throw new ContentSyncException("Channel is not available: " + label);
                    }

                    SCCRepository repository = chanTmpl.getRepository();
                    if (!repository.isAccessible()) {
                        throw new ContentSyncException("Channel is not mirrorable: " + label);
                    }

                    // Create the channel
                    Channel dbChannel = new Channel();
                    dbChannel.setBaseDir("/dev/null");
                    // from product
                    dbChannel.setChannelArch(MgrSyncUtils.getChannelArch(product.getArch(), label));
                    dbChannel.setChannelFamily(product.getChannelFamily());
                    // Checksum type is only a dummy here. spacewalk-repo-sync will update it
                    // and set it to the type used in the (last) repo to hash the primary file
                    dbChannel.setChecksumType(ChannelFactory.findChecksumTypeByLabel("sha1"));
                    // channel['summary'] = product.get('uiname')
                    // channel['description'] = product.find('description').text or channel['summary']
                    dbChannel.setLabel(label);
                    dbChannel.setName(chanTmpl.getChannelName());
                    dbChannel.setSummary(product.getFriendlyName());
                    dbChannel.setDescription(
                            Optional.ofNullable(product.getDescription()).orElse(product.getFriendlyName()));
                    dbChannel.setParentChannel(MgrSyncUtils.getChannel(chanTmpl.getParentChannelLabel()));
                    dbChannel.setProduct(MgrSyncUtils.findOrCreateChannelProduct(product));
                    dbChannel.setProductName(MgrSyncUtils.findOrCreateProductName(product.getName()));
                    dbChannel.setUpdateTag(chanTmpl.getUpdateTag());
                    dbChannel.setInstallerUpdates(repository.isInstallerUpdates());
                    dbChannel.setGPGKeyUrl(chanTmpl.getGpgKeyUrl());
                    dbChannel.setGPGKeyId(chanTmpl.getGpgKeyId());
                    dbChannel.setGPGKeyFp(chanTmpl.getGpgKeyFingerprint());

                    // Create or link the content source
                    Optional<SCCRepositoryAuth> auth = repository.getBestAuth();
                    if (auth.isPresent()) {
                        String url = contentSourceUrlOverwrite(repository, auth.get().getUrl(), mirrorUrl);
                        ContentSource source = ChannelFactory.findVendorContentSourceByRepo(url);
                        if (source == null) {
                            source = new ContentSource();
                            source.setLabel(chanTmpl.getChannelLabel());
                            source.setMetadataSigned(repository.isSigned());
                            source.setOrg(null);
                            source.setSourceUrl(url);
                            source.setType(ChannelManager.findCompatibleContentSourceType(dbChannel.getChannelArch()));
                        }
                        else {
                            // update the URL as the token might have changed
                            source.setSourceUrl(url);
                        }
                        ChannelFactory.save(source);
                        dbChannel.getSources().add(source);
                        auth.get().setContentSource(source);
                    }

                    // Save the channel
                    ChannelFactory.save(dbChannel);

                    // Create the product/channel relations
                    for (SUSEProduct p : products) {
                        SUSEProductChannel spc = new SUSEProductChannel();
                        spc.setProduct(p);
                        spc.setChannel(dbChannel);
                        spc.setMandatory(chanTmpl.isMandatory());
                        SUSEProductFactory.save(spc);
                    }
                });
    }

    /**
     * Check if a given string is a product class representing a system entitlement.
     * @param s string to check if it represents a system entitlement
     * @return true if s is a system entitlement, else false.
     */
    private static boolean isEntitlement(String s) {
        for (SystemEntitlement ent : SystemEntitlement.values()) {
            if (ent.name().equals(s)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Use original product classes and create additional with a suffix.
     * Can be used for ALPHA, BETA, TEST, etc.
     * @param label the label from the original product class
     * @param name the name from the original product class
     * @param suffix a suffix
     * @return the new created or updated channel family
     */
    private ChannelFamily createOrUpdateChannelFamily(String label, String name, String suffix) {
        // to create ALPHA and BETA families
        if (!StringUtils.isBlank(suffix)) {
            label = label + "-" + suffix;
            name = name + " (" + suffix.toUpperCase() + ")";
        }
        return createOrUpdateChannelFamily(label, name, new HashMap<>());
    }

    /**
     * Updates an existing channel family or creates and returns a new one if no channel
     * family exists with the given label.
     * @return {@link ChannelFamily}
     */
    private static ChannelFamily createOrUpdateChannelFamily(String label, String name,
                                                             Map<String, ChannelFamily> channelFamilyByLabel) {
        ChannelFamily family = Optional.ofNullable(channelFamilyByLabel).orElse(new HashMap<>()).get(label);
        if (family == null) {
            family = ChannelFamilyFactory.lookupByLabel(label, null);
        }
        if (family == null && !isEntitlement(label)) {
            family = new ChannelFamily();
            family.setLabel(label);
            family.setOrg(null);
            family.setName(StringUtils.isBlank(name) ? label : name);
            ChannelFamilyFactory.save(family);
        }
        else if (family != null && !StringUtils.isBlank(name)) {
            family.setName(name);
            ChannelFamilyFactory.save(family);
        }
        return family;
    }

    /**
     * Method for verification of the data consistency and report what is missing.
     * Verify if SCCProductJson has correct data that meets database constraints.
     * @param product {@link SCCProductJson}
     * @return comma separated list of missing attribute names
     */
    private String verifySCCProduct(SCCProductJson product) {
        List<String> missingAttributes = new ArrayList<>();
        if (product.getProductClass() == null) {
            missingAttributes.add("Product Class");
        }
        if (product.getName() == null) {
            missingAttributes.add("Name");
        }
        if (product.getVersion() == null) {
            missingAttributes.add("Version");
        }
        return StringUtils.join(missingAttributes, ", ");
    }

    /**
     * Try to read this system's UUID from file or return a cached value.
     * When the system is not registered, the backup id is returned from rhn.conf
     * When forwarding registrations to SCC, this ID identifies the proxy system
     * which sent the registration
     *
     * @return this system's UUID
     */
    public static String getUUID() {
        if (uuid == null) {
            try (BufferedReader reader = new BufferedReader(new FileReader(UUID_FILE))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("username")) {
                        uuid = line.substring(line.lastIndexOf('=') + 1);
                    }
                }
            }
            catch (FileNotFoundException e) {
                LOG.debug("Server not registered at SCC: {}", e.getMessage());
            }
            catch (IOException e) {
                LOG.warn("Unable to read SCC credentials file: {}", e.getMessage());
            }
            if (uuid == null) {
                uuid = Config.get().getString(ConfigDefaults.SCC_BACKUP_SRV_USR);
                if (uuid == null) {
                    LOG.warn("WARNING: unable to read SCC username");
                }
            }
        }
        return uuid;
    }

    /**
     * Gets the installed channel labels.
     *
     * @return the installed channel labels
     */
    private List<String> getInstalledChannelLabels() {
        List<Channel> installedChannels = ChannelFactory.listVendorChannels();
        List<String> installedChannelLabels = new ArrayList<>();
        for (Channel c : installedChannels) {
            installedChannelLabels.add(c.getLabel());
        }
        return installedChannelLabels;
    }

    /**
     * Check if one of the given URLs can be reached.
     * @param urls the urls
     * @return Returns true in case we can access at least one of this URLs, otherwise false
     */
    protected boolean accessibleUrl(List<String> urls) {
        return urls.stream().anyMatch(this::accessibleUrl);
    }

    /**
     * Check if one of the given URLs can be reached.
     * @param urls the urls
     * @param user the username
     * @param password the password
     * @return Returns true in case we can access at least one of this URLs, otherwise false
     */
    protected boolean accessibleUrl(List<String> urls, String user, String password) {
        return urls.stream().anyMatch(u -> accessibleUrl(u, user, password));
    }

    /**
     * Check if the given URL can be reached.
     * @param url the url
     * @return Returns true in case we can access this URL, otherwise false
     */
    protected boolean accessibleUrl(String url) {
        try {
            URI uri = new URI(url);
            String username = null;
            String password = null;
            if (uri.getUserInfo() != null) {
                String userInfo = uri.getUserInfo();
                username = userInfo.substring(0, userInfo.indexOf(':'));
                password = userInfo.substring(userInfo.indexOf(':') + 1);
            }
            return accessibleUrl(url, username, password);
        }
        catch (URISyntaxException e) {
            LOG.error("accessibleUrl: {} URISyntaxException {}", url, e.getMessage(), e);
        }
        return false;
    }

    /**
     * Check if the given URL can be reached using provided username and password
     * @param url the url
     * @param user the username
     * @param password the password
     * @return Returns true in case we can access this URL, otherwise false
     */
    protected boolean accessibleUrl(String url, String user, String password) {
        try {
            URI uri = new URI(url);

            // Build full URL to test
            if (uri.getScheme().equals("file")) {
                Path testUrlPath = new File(Objects.toString(uri.getRawPath(), "/")).toPath();
                boolean res = Files.isReadable(testUrlPath);
                LOG.debug("accessibleUrl:{} {}", testUrlPath, res);
                return res;
            }
            else {
                // Verify the mirrored repo by sending a HEAD request
                int status = MgrSyncUtils.sendHeadRequest(uri.toString(),
                        user, password).getStatusLine().getStatusCode();
                LOG.debug("accessibleUrl: {} returned status {}", uri, status);
                return (status == HttpURLConnection.HTTP_OK);
            }
        }
        catch (IOException e) {
            LOG.error("accessibleUrl: {} IOException {}", url, e.getMessage(), e);
        }
        catch (URISyntaxException e) {
            LOG.error("accessibleUrl: {} URISyntaxException {}", url, e.getMessage(), e);
        }
        return false;
    }

    /**
     * Get an instance of {@link SCCWebClient} and configure it to use localpath, if
     * such is setup in /etc/rhn/rhn.conf
     *
     * @param source sync source to get content from
     * @throws SCCClientException when access is not possible
     * @return {@link SCCWebClient}
     */
    protected SCCClient getSCCClient(ContentSyncSource source) throws SCCClientException, ContentSyncSourceException {
        return source.getClient(getUUID(), tmpLoggingDir);
    }

    /**
     * Returns true if the given label is reserved: eg. used by a vendor channel
     *
     * @param label Label
     * @return true if the given label reserved.
     */
    public static boolean isChannelLabelReserved(String label) {
        return SUSEProductFactory.lookupByChannelLabelFirst(label).isPresent();
    }

    /**
     * Returns true if the given name reserved. eg. used by a vendor channel
     *
     * eg: name of vendor channel
     * @param name name
     * @return true if the given name reserved.
     */
    public static boolean isChannelNameReserved(String name) {
        return !SUSEProductFactory.lookupByChannelName(name).isEmpty();
    }

    private boolean isRepoSigned(boolean signedDefault) {
        if (isPeripheral) {
            return hubHasSignedMetadata;
        }
        return signedDefault;
    }

    /**
     * Returns true when a valid Subscription for the SUSE Manager Tools Channel
     * is available
     *
     * @return true if we have a Tools Subscription, otherwise false
     */
    public boolean hasToolsChannelSubscription() {
        return SCCCachingFactory.lookupSubscriptions()
                .stream()
                .filter(s -> s.getStatus().equals("ACTIVE") &&
                        s.getExpiresAt().after(new Date()) &&
                        (s.getStartsAt() == null || s.getStartsAt().before(new Date())))
                .map(SCCSubscription::getProducts)
                .flatMap(Set::stream)
                .filter(p -> p.getChannelFamily() != null)
                .anyMatch(p -> toolsChannelFamilies.contains(p.getChannelFamily().getLabel()));
    }

    /**
     * Check if Tools Channels can be synced via Cloud RMT Infrastructure.
     * In PAYG scenario, we do not have a subscription, but we have access
     * via the Cloud RMT server and can mirror them.
     * @return return true if we can sync tools channels via Cloud RMT, otherwise false
     */
    public boolean canSyncToolsChannelViaCloudRMT() {
        return SCCCachingFactory.lookupRepositoryAuth().stream()
                .filter(a -> a.cloudRmtAuth().isPresent())
                .map(SCCRepositoryAuth::getRepo)
                .flatMap(r -> r.getChannelTemplates().stream())
                .map(ChannelTemplate::getProduct)
                .filter(p -> p.getChannelFamily() != null)
                .anyMatch(p -> toolsChannelFamilies.contains(p.getChannelFamily().getLabel()));
    }
}
