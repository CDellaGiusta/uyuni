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

import com.redhat.rhn.common.conf.ConfigDefaults;
import com.redhat.rhn.common.util.http.HttpClientAdapter;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.ChannelArch;
import com.redhat.rhn.domain.channel.ChannelFactory;
import com.redhat.rhn.domain.channel.ChannelProduct;
import com.redhat.rhn.domain.channel.ProductName;
import com.redhat.rhn.domain.product.SUSEProduct;
import com.redhat.rhn.domain.rhnpackage.PackageArch;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpHead;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Utility methods to be used in {@link ContentSyncManager} related code.
 */
public class MgrSyncUtils {
    // Logger instance
    private static final Logger LOG = LogManager.getLogger(MgrSyncUtils.class);

    // Source URL handling
    private static final String OFFICIAL_NOVELL_UPDATE_HOST = "nu.novell.com";
    private static final List<String> PRODUCT_ARCHS = Arrays.asList("i386", "i486", "i586", "i686", "ia64", "ppc64le",
            "ppc64", "ppc", "s390x", "s390", "x86_64", "aarch64", "amd64", "arm64");

    // No instances should be created
    private MgrSyncUtils() {
    }

    /**
     * Send a HEAD request to a given URL to verify accessibility with given credentials.
     *
     * @param url the URL to verify
     * @param username username for authentication (pass null for unauthenticated requests)
     * @param password password for authentication (pass null for unauthenticated requests)
     * @return the response code of the request
     * @throws IOException in case of an error
     */
    public static HttpResponse sendHeadRequest(String url, String username, String password)
            throws IOException {
        return sendHeadRequest(url, username, password, false);
    }

    /**
     * Send a HEAD request to verify a proxy server (ignoring the "no_proxy" setting).
     *
     * @param url the URL to use for verification
     * @return true if return code of HTTP request is 200, otherwise false
     * @throws IOException in case of an error
     */
    public static boolean verifyProxy(String url) throws IOException {
        return sendHeadRequest(url, null, null, true).getStatusLine()
                .getStatusCode() == HttpStatus.SC_OK;
    }

    /**
     * Send a HEAD request to a given URL to verify accessibility with given credentials.
     *
     * @param url the URL to verify
     * @param username username for authentication (pass null for unauthenticated requests)
     * @param password password for authentication (pass null for unauthenticated requests)
     * @param ignoreNoProxy set true to ignore the "no_proxy" setting
     * @return the response code of the request
     * @throws IOException in case of an error
     */
    private static HttpResponse sendHeadRequest(String url, String username,
            String password, boolean ignoreNoProxy) throws IOException {
        HttpClientAdapter httpClient = new HttpClientAdapter();
        HttpHead headRequest = new HttpHead(url);
        try {
            return httpClient.executeRequest(
                    headRequest, username, password, ignoreNoProxy);
        }
        finally {
            headRequest.releaseConnection();
        }
    }

    /**
     * Handle special cases where SUSE arch names differ from the RedHat ones.
     *
     * @param packageArch we want to get the arch from
     * @param channelLabel alternative try to find the arch in the channelLabel
     * @return channel arch object
     */
    public static ChannelArch getChannelArch(PackageArch packageArch, String channelLabel) {
        String arch = "x86_64";
        if (packageArch != null) {
            arch = packageArch.getLabel();
        }
        else {
            arch = PRODUCT_ARCHS.stream().filter(channelLabel::contains).findFirst().orElse(arch);
        }
        switch (arch) {
            case "i686":
            case "i586":
            case "i486":
            case "i386":
                arch = "ia32";
                break;
            case "ppc64":
                arch = "ppc";
                break;
            case "amd64":
                arch = "amd64-deb";
                break;
            case "arm64":
                arch = "arm64-deb";
                break;
            default:
                // keep arch unchanged
                break;
        }
        return ChannelFactory.findArchByLabel("channel-" + arch);
    }

    /**
     * Get the channel for a given channel label.
     * If label is null it returns null. If the channel label is not found
     * it throws an exception.
     *
     * @param label the label
     * @return the channel
     * @throws ContentSyncException if the parent channel is not installed
     */
    public static Channel getChannel(String label) throws ContentSyncException {
        Channel channel = null;
        if (label != null) {
            channel = ChannelFactory.lookupByLabel(label);
            if (channel == null) {
                throw new ContentSyncException("The parent channel is not installed: " + label);
            }
        }
        return channel;
    }

    /**
     * Find a {@link ChannelProduct} or create it if necessary and return it.
     *
     * @param product product to find or create
     * @return channel product
     */
    public static ChannelProduct findOrCreateChannelProduct(SUSEProduct product) {
        return findOrCreateChannelProduct(product.getName(), product.getVersion());
    }

    /**
     * Find a {@link ChannelProduct} or create it if necessary and return it.
     *
     * @param productName    name of the product to find or create
     * @param productVersion version of the product to find or create
     * @return channel product
     */
    public static ChannelProduct findOrCreateChannelProduct(String productName, String productVersion) {
        ChannelProduct p = ChannelFactory.findChannelProduct(
                productName, productVersion);
        if (p == null) {
            p = new ChannelProduct();
            p.setProduct(productName);
            p.setVersion(productVersion);
            p.setBeta(false);
            ChannelFactory.save(p);
        }
        return p;
    }

    /**
     * Find a {@link ProductName} or create it if necessary and return it.
     * @param name channel
     * @return product name
     */
    public static ProductName findOrCreateProductName(String name) {
        ProductName productName = ChannelFactory.lookupProductNameByLabel(name);
        if (productName == null) {
            productName = new ProductName();
            productName.setLabel(name);
            productName.setName(name);
            ChannelFactory.save(productName);
        }
        return productName;
    }

    /**
     * Converts the specified network url to a file system url
     * @param urlString the url
     * @param name the name of the repo
     * @return the file system URI
     */
    public static URI urlToFSPath(String urlString, String name) {
        return ConfigDefaults.get().getOfflineMirrorDir()
            .map(sccDataPath -> urlToFSPath(urlString, name, Paths.get(sccDataPath)))
            .orElseThrow(() -> new IllegalArgumentException("No value set for offline mirror directory"));
    }

    /**
     * Convert network URL to file system URL.
     * <p>
     * 1. URL point to localhost, return the normal URL, we have access
     * 2. URL from updates.suse.com, return the path
     * 3. legacy SMT mirror URL /repo/RPMMD/&lt;repo name&gt; if it exists
     * 4. finally, return host + path as path component
     * <p>
     * A mirrorlist URL with query paramater is converted to a path:
     * - key=value => key/value
     * - sort alphabetically
     * - join with a /
     * Example:
     * http://mirrorlist.centos.org/?release=8&arch=x86_64&repo=AppStream&infra=stock
     * file://mirrorlist.centos.org/arch/x86_64/infra/stock/release/8/repo/AppStream
     *
     * @param urlString url
     * @param name repo name
     * @param sccDataPath the expected path of the scc data, to validate the resulting url
     * @return file URI
     */
    public static URI urlToFSPath(String urlString, String name, Path sccDataPath) {
        String host = "";
        String path = File.separator;
        try {
            URI uri = new URI(urlString);
            host = uri.getHost();
            path = uri.getPath();

            // Case 1
            if ("localhost".equals(host)) {
                return uri;
            }
            String qPath = Arrays.stream(Optional.ofNullable(uri.getQuery()).orElse("").split("&"))
                    .filter(p -> !p.isEmpty())
                    .filter(p -> !isAuthToken(p)) // filter out possible auth tokens
                    .map(p -> String.join(File.separator, p.split("=", 2)))
                    .sorted()
                    .collect(Collectors.joining(File.separator));
            if (!qPath.isBlank()) {
                path = Paths.get(path, qPath).toString();
            }
        }
        catch (URISyntaxException e) {
            LOG.warn("Unable to parse URL: {}", urlString);
        }

        if (sccDataPath == null) {
            throw new ContentSyncException("No local mirror path configured");
        }
        File dataPath = sccDataPath.toFile();
        // Case 4
        File mirrorPath = new File(dataPath.getAbsolutePath(), host + File.separator + path);

        // Case 2
        if (host.endsWith(ConfigDefaults.get().getOfficialUpdateHostDomain()) ||
                host.equals(OFFICIAL_NOVELL_UPDATE_HOST)) {
            mirrorPath = new File(dataPath.getAbsolutePath(), path);
            LOG.info("SCC mirrorpath: {}", mirrorPath);
        }
        else if (name != null) {
            // Case 3
            // everything after the first space are suffixes added to make things unique
            String[] parts  = URLDecoder.decode(name, StandardCharsets.UTF_8).split("[\\s/]");
            if (!(parts[0].isBlank() || parts[0].equals(".."))) {
                File oldMirrorPath = Paths.get(dataPath.getAbsolutePath(), "repo", "RPMMD", parts[0]).toFile();
                LOG.info("SMT mirrorpath for '{}': {}", name, oldMirrorPath);
                if (oldMirrorPath.exists()) {
                    mirrorPath = oldMirrorPath;
                }
                else {
                    // mirror in a common folder (bsc#1201753)
                    File commonMirrorPath = Paths.get(dataPath.getAbsolutePath(), path).toFile();
                    LOG.info("Common mirrorpath for '{}': {}", name, commonMirrorPath);
                    if (commonMirrorPath.exists()) {
                        mirrorPath = commonMirrorPath;
                    }
                    else {
                        LOG.info("Default mirrorpath for '{}': {}", name, mirrorPath);
                    }
                }
            }
        }
        else {
            LOG.info("Default mirrorpath: {}", mirrorPath);
        }
        Path cleanPath = mirrorPath.toPath().normalize();
        if (!cleanPath.startsWith(sccDataPath)) {
            LOG.error("Resulting path outside of configured directory {}: {}", dataPath, urlString);
            cleanPath = dataPath.toPath();
        }
        return cleanPath.toUri().normalize();
    }

    /**
     * Check, if a given string is an authentication token. The given string must not contain '&' signs
     * which are used to separate query parameters. The expected input is a single query paramater
     * @param queryParam a single query parameter string to test
     * @return true if this is likely an authentication token. Otherwise false
     */
    public static boolean isAuthToken(String queryParam) {
        if (queryParam.isBlank()) {
            LOG.debug("empty queryParam is not an auth token");
            return false;
        }
        else if (queryParam.contains("&")) {
            throw new ContentSyncException("token must not contain the ampersand sign");
        }
        //     Could be an JWT token
        boolean ret = !queryParam.contains("=") ||
                // Our CDN tokens use this key
                queryParam.startsWith("dlauth=") ||
                // typical Akamai token values
                (queryParam.contains("exp=") && queryParam.contains("hmac="));
        LOG.debug("{} isAuthToken: {}", queryParam, ret);
        return ret;
    }
}
