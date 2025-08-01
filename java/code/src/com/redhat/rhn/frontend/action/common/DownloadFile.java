/*
 * Copyright (c) 2009--2018 Red Hat, Inc.
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
package com.redhat.rhn.frontend.action.common;

import com.redhat.rhn.common.conf.Config;
import com.redhat.rhn.common.conf.ConfigDefaults;
import com.redhat.rhn.common.security.PermissionException;
import com.redhat.rhn.common.security.SessionSwap;
import com.redhat.rhn.common.util.FileUtils;
import com.redhat.rhn.common.util.SHA256Crypt;
import com.redhat.rhn.common.util.download.ByteArrayStreamInfo;
import com.redhat.rhn.domain.action.script.ScriptActionDetails;
import com.redhat.rhn.domain.action.script.ScriptResult;
import com.redhat.rhn.domain.action.script.ScriptRunAction;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.ChannelFactory;
import com.redhat.rhn.domain.channel.MediaProducts;
import com.redhat.rhn.domain.common.CommonFactory;
import com.redhat.rhn.domain.common.TinyUrl;
import com.redhat.rhn.domain.kickstart.KickstartFactory;
import com.redhat.rhn.domain.kickstart.KickstartSession;
import com.redhat.rhn.domain.kickstart.KickstartSessionState;
import com.redhat.rhn.domain.kickstart.KickstartableTree;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.org.OrgFactory;
import com.redhat.rhn.domain.rhnpackage.Package;
import com.redhat.rhn.domain.rhnpackage.PackageFactory;
import com.redhat.rhn.domain.rhnpackage.PackageSource;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.domain.user.UserFactory;
import com.redhat.rhn.frontend.action.kickstart.KickstartHelper;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnHelper;
import com.redhat.rhn.manager.action.ActionManager;
import com.redhat.rhn.manager.channel.ChannelManager;
import com.redhat.rhn.manager.download.DownloadManager;
import com.redhat.rhn.manager.download.UnknownDownloadTypeException;
import com.redhat.rhn.manager.kickstart.KickstartManager;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.apache.struts.actions.DownloadAction;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.RandomAccessFile;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * ChannelPackagesAction
 */
public class DownloadFile extends DownloadAction {


    private static Logger log = LogManager.getLogger(DownloadFile.class);

    private static final String PARAMS = "params";
    private static final String TYPE = "type";
    private static final String HASH = "hash";
    private static final String EXPIRE = "expire";
    private static final String USERID = "userid";
    private static final String FILEID = "fileid";
    private static final String FILENAME = "filename";
    private static final String CHILD = "child";
    private static final String TREE = "tree";
    private static final String SESSION = "session";
    private static final String URL_STRING = "url";
    private static final String CONTENT_TYPE_OCTET_STREAM = "application/octet-stream";
    private static final String CONTENT_TYPE_TEXT_PLAIN = "text/plain";
    private static final String CONTENT_TYPE_TEXT_XML = "text/xml";
    private static final Long DOWNLOAD_REPO_LOG_LENGTH = 102400L;
    private static final Long DOWNLOAD_REPO_LOG_MIN_LENGTH = 10L;

    /** {@inheritDoc} */
    @Override
    public ActionForward execute(ActionMapping mapping,
            ActionForm formIn,
            HttpServletRequest request,
            HttpServletResponse response) throws Exception {

        String url = RhnHelper.getParameterWithSpecialCharacters(request, "url");
        if (url == null) {
            return mapping.findForward("error");
        }
        log.debug("url : [{}]", url);
        if (url.startsWith("/ty/")) {
            url = url.replaceFirst("/ty/", "");
            String[] splits = url.split("/");
            log.debug(splits[0]);
            TinyUrl ty = CommonFactory.lookupTinyUrl(splits[0]);
            splits[0] = ty.getUrl();
            url = String.join("/", splits);
            log.debug(url);
        }
        if (url.startsWith("/ks/dist")) {
            log.debug("URL is ks dist..");
            ActionForward error = handleKickstartDownload(request, response, url, mapping);
            log.debug("Done handling ks download");
            if (error != null) {
                log.debug("returning null");
                return null;
            }
        }
        else if (url.startsWith("/cblr/svc/op/ks/")) {
            url = url.replaceFirst("ks", "autoinstall");
            Map<String, Object> params = new HashMap<>();
            params.put(TYPE,  DownloadManager.DOWNLOAD_TYPE_COBBLER);
            params.put(URL_STRING, url);
            request.setAttribute(PARAMS, params);
            return super.execute(mapping, formIn, request, response);
        }
        else if (url.startsWith("/cblr/svc/op/autoinstall/")) {
            Map<String, Object> params = new HashMap<>();
            params.put(TYPE,  DownloadManager.DOWNLOAD_TYPE_COBBLER);
            params.put(URL_STRING, url);
            request.setAttribute(PARAMS, params);
            return super.execute(mapping, formIn, request, response);
        }
        else if (url.startsWith("/cobbler_api")) {
            Map<String, Object> params = new HashMap<>();
            params.put(TYPE,  DownloadManager.DOWNLOAD_TYPE_COBBLER_API);
            request.setAttribute(PARAMS, params);
            return super.execute(mapping, formIn, request, response);
        }
        else {
            ActionForward error = handleUserDownload(request, url, mapping);
            if (error != null) {
                return error;
            }
        }
        try {
            log.debug("Calling super.execute");
            super.execute(mapping, formIn, request, response);
        }
        catch (Exception e) {
            log.error("Package retrieval error on file download url: {}", url, e);
            return mapping.findForward("error");
        }

        return null;
    }

    /**
     * Parse a /ks/dist url
     *  The following URLS are accepted:
     *   /ks/dist/tree-label/path/to/file.rpm
     *    /ks/dist/org/#/tree-label/path/to/file
     *    /ks/dist/session/HEX/tree-label/path/to/file.rpm
     *    /ks/dist/tree-label/child/child-chan-label/path/to/file.rpm
     *
     * @param url the url to parse
     * @return a map with the following params:
     *     label  (req)
     *     path    (req)
     *     session  (opt)
     *     orgId    (opt)
     *     child    (opt)
     */
    public static Map<String, String> parseDistUrl(String url) {
        Map<String, String> ret = new HashMap<>();

        if (url.charAt(0) == '/') {
            url = url.substring(1);
        }

        String[] split = url.split("/");

        try {
            int labelPos = 2;
            if (split[2].equals("org")) {
                ret.put("orgId",  split[3]);
                labelPos = 4;
            }
            else if (split[2].equals(SESSION)) {
                ret.put(SESSION, split[3]);
                labelPos = 4;
            }
            else if (split[2].equals(CHILD)) {
                ret.put(CHILD, split[3]);
                labelPos = 4;
            }

            ret.put("label", split[labelPos]);
            StringBuilder path = new StringBuilder();
            for (int i = labelPos + 1; i < split.length; i++) {
                path.append("/").append(split[i]);
            }
            ret.put("path", URLDecoder.decode(path.toString(), StandardCharsets.UTF_8));
        }
        catch (ArrayIndexOutOfBoundsException e) {
            return null;
        }
        return ret;
    }

    private ActionForward handleKickstartDownload(HttpServletRequest request, HttpServletResponse response,
                                                  String url, ActionMapping mapping) throws IOException {

        log.debug("URL : {}", url);

        Map<String, String> map = DownloadFile.parseDistUrl(url);

        if (map == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return mapping.findForward("error");
        }

        String path = map.get("path");
        String label = map.get("label");
        Long orgId = null;
        if (map.containsKey("orgId")) {
            try {
                orgId = Long.parseLong(map.get("orgId"));
            }
            catch (NumberFormatException e) {
                // Do nothing
            }
        }

        KickstartSession ksession = null;
        if (map.containsKey(SESSION)) {
            String sessionId = SessionSwap.extractData(map.get(SESSION))[0];
            ksession = KickstartFactory.
            lookupKickstartSessionById(Long.valueOf(sessionId));
        }

        log.debug("computed path to just the file: {}", path);
        log.debug("Tree label to lookup: {}", label);

        KickstartableTree tree = null;
        if (orgId != null) {
            Org org = OrgFactory.lookupById(orgId);
            if (org != null) {
                tree = KickstartFactory.lookupKickstartTreeByLabel(label, org);
            }
        }
        else if (ksession != null) {
            tree = ksession.getKstree();
        }
        else {
            tree = KickstartFactory.lookupKickstartTreeByLabel(label);
        }

        if (map.containsKey(CHILD) && !Config.get().getBoolean("ks_restrict_child_channels")) {
            Channel child = ChannelFactory.lookupByLabel(map.get(CHILD));
            if (child == null || tree == null || child.getParentChannel() == null ||
                    !child.getParentChannel().equals(tree.getChannel())) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return mapping.findForward("error");
            }
            Map<String, Object> params = new HashMap<>();
            params.put(TYPE, DownloadManager.DOWNLOAD_TYPE_KICKSTART);
            params.put(TREE, tree);
            params.put(CHILD, child);
            params.put(FILENAME, path);
            request.setAttribute(PARAMS, params);
            return null;
        }

        if (tree == null) {
            log.error("Tree not found.");
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return mapping.findForward("error");
        }
        Map<String, Object> params = new HashMap<>();
        params.put(TYPE, DownloadManager.DOWNLOAD_TYPE_KICKSTART);
        params.put(TREE, tree);
        params.put(FILENAME, path);
        if (ksession != null) {
            params.put(SESSION, ksession);
        }
        request.setAttribute(PARAMS, params);
        return null;
    }


    private ActionForward handleUserDownload(HttpServletRequest request, String url,
            ActionMapping mapping) {
        List<String> split = Arrays.asList(url.split("/"));
        Iterator<String> it = split.iterator();
        Map<String, Object> params = new HashMap<>();

        String type = getNextValue(it);
        String hash = getNextValue(it);
        Long expire = null;
        Long userId = null;
        Long fileId = null;
        try {
            expire = Long.valueOf(getNextValue(it));
            userId = Long.valueOf(getNextValue(it));
            fileId = Long.valueOf(getNextValue(it));
        }
        catch (NumberFormatException e) {
            log.error("Error parsing file download url: {}", url);
            return mapping.findForward("error");
        }
        String filename = getNextValue(it);

        params.put(TYPE, type);
        params.put(HASH, hash);
        params.put(EXPIRE, expire);
        params.put(USERID, userId);
        params.put(FILEID, fileId);
        params.put(FILENAME, filename);
        request.setAttribute(PARAMS, params);

        //If expire is at 0, then expiration is disabled for the download
        //    we'll validate the SHA1 token to make sure someone didn't hack
        //      it in the next step.
        if (expire != 0 && Calendar.getInstance().getTimeInMillis() > expire) {
            log.error("File download url has expired: {}", url);
            return mapping.findForward("error");
        }

        User user = UserFactory.lookupById(userId);
        if (hash == null || !hash.equals(DownloadManager.getFileSHA1Token(fileId, filename, user, expire, type))) {
            log.error("Invalid hash on file download url: {}", url);
            return mapping.findForward("error");
        }

        return null;
    }

    @Override
    @SuppressWarnings("unchecked")
    protected StreamInfo getStreamInfo(ActionMapping mapping, ActionForm form,
            HttpServletRequest request, HttpServletResponse response) throws Exception {

        String path;
        Map<String, Object> params = (Map<String, Object>) request.getAttribute(PARAMS);
        String type = (String) params.get(TYPE);
        User currentUser = new RequestContext(request).getCurrentUser();
        if (type.equals(DownloadManager.DOWNLOAD_TYPE_KICKSTART)) {
            return getStreamInfoKickstart(request, response);
        }
        else if (type.equals(DownloadManager.DOWNLOAD_TYPE_COBBLER)) {
            String url = ConfigDefaults.get().getCobblerServerUrl() + params.get(URL_STRING);
            KickstartHelper helper = new KickstartHelper(request);
            String data;
            if (helper.isProxyRequest()) {
                data = KickstartManager.getInstance().renderKickstart(helper.getKickstartHost(), url);
            }
            else {
                data = KickstartManager.getInstance().renderKickstart(url);
            }
            setContentInfo(response, data.getBytes().length, CONTENT_TYPE_TEXT_PLAIN);
            return getStream(data.getBytes(), CONTENT_TYPE_TEXT_PLAIN);
        }
        else if (type.equals(DownloadManager.DOWNLOAD_TYPE_COBBLER_API)) {
            // read data from POST body
            StringBuilder postData = new StringBuilder();
            String line;
            BufferedReader reader = request.getReader();
            while ((line = reader.readLine()) != null) {
                postData.append(line);
            }

            // Send data
            URL url = new URL(ConfigDefaults.get().getCobblerServerUrl() + "/cobbler_api");
            URLConnection conn = url.openConnection();
            conn.setDoOutput(true);
            OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
            // this will write POST /download//cobbler_api instead of
            // POST /cobbler_api, but cobbler do not mind
            wr.write(postData.toString(), 0, postData.length());
            wr.flush();
            conn.connect();

            // Get the response
            StringBuilder output = new StringBuilder();
            BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            while ((line = rd.readLine()) != null) {
                output.append(line);
            }
            wr.close();

            KickstartHelper helper = new KickstartHelper(request);
            String outputStr = output.toString();
            if (helper.isProxyRequest()) {
                // Search/replacing all instances of cobbler host with host
                // we pass in, for use with Spacewalk Proxy.
                outputStr = outputStr.replaceAll(ConfigDefaults.get().getJavaHostname(), helper.getForwardedHost());
            }

            setContentInfo(response, outputStr.length(), CONTENT_TYPE_TEXT_XML);
            return getStream(outputStr.getBytes(), CONTENT_TYPE_TEXT_XML);
        }
        else {
            Long fileId = (Long) params.get(FILEID);
            Long userid = (Long) params.get(USERID);
            User user = UserFactory.lookupById(userid);
            if (type.equals(DownloadManager.DOWNLOAD_TYPE_PACKAGE)) {
                Package pack = PackageFactory.lookupByIdAndOrg(fileId, user.getOrg());
                setContentInfo(response, pack.getPackageSize(), CONTENT_TYPE_OCTET_STREAM);
                path = Config.get().getString(ConfigDefaults.MOUNT_POINT) + File.separator + pack.getPath();
                return getStreamForPath(path, CONTENT_TYPE_OCTET_STREAM);
            }
            else if (type.equals(DownloadManager.DOWNLOAD_TYPE_SOURCE)) {
                Package pack = PackageFactory.lookupByIdAndOrg(fileId, user.getOrg());
                List<PackageSource> src = PackageFactory.lookupPackageSources(pack);
                if (!src.isEmpty()) {
                    setContentInfo(response, src.get(0).getPackageSize(), CONTENT_TYPE_OCTET_STREAM);
                    path = Config.get().getString(ConfigDefaults.MOUNT_POINT) + File.separator + src.get(0).getPath();
                    return getStreamForPath(path, CONTENT_TYPE_OCTET_STREAM);
                }
            }
            else if (type.equals(DownloadManager.DOWNLOAD_TYPE_REPO_LOG)) {
                Channel c = ChannelFactory.lookupById(fileId);
                ChannelManager.verifyChannelAdmin(user, fileId);
                StringBuilder output = new StringBuilder();
                for (String fileName : ChannelManager.getLatestSyncLogFiles(c)) {
                    try (RandomAccessFile file = new RandomAccessFile(fileName, "r")) {
                        long fileLength = file.length();
                        if (fileLength > DOWNLOAD_REPO_LOG_LENGTH) {
                            file.seek(fileLength - DOWNLOAD_REPO_LOG_LENGTH);
                            // throw away text till end of the actual line
                            file.readLine();
                        }
                        else {
                            file.seek(0);
                        }
                        String line;
                        while ((line = file.readLine()) != null) {
                            output.append(line);
                            output.append("\n");
                        }
                    }
                     if (output.length() > DOWNLOAD_REPO_LOG_MIN_LENGTH) {
                        break;
                    }
                }

                setContentInfo(response, output.length(), CONTENT_TYPE_TEXT_PLAIN);
                return getStream(output.toString().getBytes(), CONTENT_TYPE_TEXT_PLAIN);
            }
            else if (type.equals(DownloadManager.DOWNLOAD_TYPE_SCRIPTRAWOUTPUT)) {
                if (!user.equals(currentUser)) {
                    throw new PermissionException("missing permission for download link");
                }
                ScriptRunAction action = (ScriptRunAction) ActionManager.lookupAction(user, fileId);
                ScriptActionDetails details = action.getScriptActionDetails();

                StringBuilder results = new StringBuilder();
                if (details.getResults() != null) {
                    for (ScriptResult r : details.getResults()) {
                        results.append(r.getOutputContents());
                    }
                }
                return getStream(results.toString().getBytes(), CONTENT_TYPE_TEXT_PLAIN);
            }
        }

        throw new UnknownDownloadTypeException("The specified download type " + type + " is not currently supported");
    }

    @SuppressWarnings("unchecked")
    private StreamInfo getStreamInfoKickstart(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        Map<String, Object> params = (Map<String, Object>) request.getAttribute(PARAMS);
        String path = (String) params.get(FILENAME);
        log.debug("getStreamInfo KICKSTART type, path: {}", path);
        String diskPath = null;
        String kickstartMount = Config.get().getString(ConfigDefaults.MOUNT_POINT);
        String fileName;
        KickstartSession ksession = (KickstartSession) params.get(SESSION);
        KickstartSessionState newState = null;
        KickstartableTree tree = (KickstartableTree) params.get(TREE);
        Package rpmPackage = null;
        Channel child = (Channel) params.get(CHILD);

        if (tree.getBasePath().indexOf(kickstartMount) == 0) {
            log.debug("Trimming mount because tree is explicitly rooted to the mount point");
            kickstartMount = "";
        }
        // If the tree is rooted somewhere other than
        // /var/satellite then no need to prepend it.
        if (tree.getBasePath().startsWith(File.separator)) {
            log.debug("Tree isn't rooted at /var/satellite, lets just use basepath");
            kickstartMount = "";
        }
        // Searching for RPM
        if (path.endsWith(".rpm")) {
            String[] split = StringUtils.split(path, '/');
            fileName = split[split.length - 1];
            String checksum = split[split.length - 2];
            if (checksum.matches("^[0-9a-f]{32,}$")) {
                // ChannelFactory.lookupPackageByFilename* uses "like" for the path
                // this works also with checksum/fileName
                fileName = checksum + File.separator + fileName;
            }
            log.debug("RPM filename: {}", fileName);
            Channel channel = tree.getChannel();
            if (child != null) {
                channel = child;
            }

            if (child != null || !tree.getInstallType().isSUSE() ||
                    tree.getKernelOptions().contains("useonlinerepo")) {
                String byteRange = request.getHeader("Range");
                if (byteRange != null) {
                    Pattern rangeRegex = Pattern.compile("bytes=(\\d+)-(\\d+)", Pattern.CASE_INSENSITIVE);
                    Matcher match = rangeRegex.matcher(byteRange);
                    int newHeaderEnd = 0;
                    int newHeaderStart = 0;

                    if (match.find()) {
                        newHeaderStart = Integer.parseInt(match.group(1));
                        newHeaderEnd = Integer.parseInt(match.group(2));
                        int modulo = newHeaderEnd % 8;
                        if (modulo > 0) {
                            newHeaderEnd = newHeaderEnd + 8 - modulo;
                        }
                    }
                    rpmPackage = ChannelFactory.lookupPackageByFilenameAndRange(
                            channel, fileName, newHeaderStart, newHeaderEnd);
                }
                else {
                    rpmPackage = ChannelFactory.lookupPackageByFilename(channel, fileName);
                }
            }

            if (rpmPackage != null) {
                diskPath = Config.get().getString(ConfigDefaults.MOUNT_POINT) + File.separator + rpmPackage.getPath();
                log.debug("found package :: diskPath path: {}", diskPath);
                newState = KickstartFactory.lookupSessionStateByLabel(KickstartSessionState.IN_PROGRESS);
            }
            else {
                log.debug("Package was not in channel, looking in distro path.");
            }
        }
        // either it's not an rpm, or we didn't find it in the channel
        // check for dir pings, virt manager or install, bz #345721
        if (diskPath == null) {
            if (child == null) {
                if (path.contains("repodata/") && tree.getKernelOptions().contains("useonlinerepo")) {
                    if (path.endsWith("/comps.xml")) {
                        diskPath = Config.get().getString(ConfigDefaults.MOUNT_POINT) +
                            File.separator + tree.getChannel().getComps().getRelativeFilename();
                    }
                    else if (path.endsWith("/modules.yaml")) {
                        diskPath = Config.get().getString(ConfigDefaults.MOUNT_POINT) +
                            File.separator + tree.getChannel().getModules().getRelativeFilename();
                    }
                    else {
                        String[] split = StringUtils.split(path, '/');
                        if (split[0].equals("repodata")) {
                            split[0] = tree.getChannel().getLabel();
                        }
                        diskPath = Config.get().getString(ConfigDefaults.REPOMD_CACHE_MOUNT_POINT, "/pub") +
                                File.separator + Config.get().getString("repomd_path_prefix", "rhn/repodata/") +
                                File.separator + StringUtils.join(split, '/');
                    }
                }
                else if (tree.getKernelOptions().contains("useonlinerepo") && path.endsWith("/media.1/products")) {
                    MediaProducts mediaProducts = Optional.ofNullable(tree.getChannel().getMediaProducts())
                            .orElse(ChannelManager.getOriginalChannel(tree.getChannel()).getMediaProducts());
                    if (mediaProducts != null) {
                        diskPath = Config.get().getString(ConfigDefaults.MOUNT_POINT) +
                                File.separator + mediaProducts.getRelativeFilename();
                    }
                    else {
                        diskPath = kickstartMount + File.separator + tree.getBasePath() + path;
                    }
                }
                else {
                    diskPath = kickstartMount + File.separator + tree.getBasePath() + path;
                }
            }
            else if (path.endsWith("/comps.xml")) {
                diskPath = Config.get().getString(ConfigDefaults.MOUNT_POINT) +
                    File.separator + child.getComps().getRelativeFilename();
            }
            else if (path.endsWith("/modules.yaml")) {
                diskPath = Config.get().getString(ConfigDefaults.MOUNT_POINT) +
                    File.separator + child.getModules().getRelativeFilename();
            }
            else {
                String[] split = StringUtils.split(path, '/');
                if (split.length > 0 && split[0].equals("repodata")) {
                    split[0] = child.getLabel();
                }
                diskPath = Config.get().getString(ConfigDefaults.REPOMD_CACHE_MOUNT_POINT, "/pub") +
                        File.separator + Config.get().getString("repomd_path_prefix", "rhn/repodata/") +
                        File.separator + StringUtils.join(split, File.separator);
            }

            log.debug("DirCheck path: {}", diskPath);
            File actualFile = new File(diskPath);
            if (actualFile.exists() && actualFile.isDirectory()) {
                log.debug("Directory hit.  just return 200");
                response.setContentLength(0);
                response.setStatus(HttpServletResponse.SC_OK);
                return getStream("".getBytes(), CONTENT_TYPE_TEXT_PLAIN);
            }
            else if (actualFile.exists()) {
                log.debug("Looks like it is an actual file and it exists.");
                newState = KickstartFactory.lookupSessionStateByLabel(KickstartSessionState.STARTED);

            }
            else {
                log.error("{} Not Found .. 404!", diskPath);
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return getStream("".getBytes(), CONTENT_TYPE_TEXT_PLAIN);
            }
        }
        log.debug("Final path before returning getStreamForPath(): {}", diskPath);
        if (log.isDebugEnabled()) {
            Enumeration<String> e = request.getHeaderNames();
            while (e.hasMoreElements()) {
                String name = e.nextElement();
                log.debug("header: [{}]: {}", name, request.getHeader(name));
            }
        }
        if (request.getMethod().equals("HEAD")) {
            log.debug("Method is HEAD .. serving checksum");
            return manualServeChecksum(response, rpmPackage, diskPath);
        }
        else if (request.getHeader("Range") != null) {
            log.debug("range detected.  serving chunk of file");
            String range = request.getHeader("Range");
            return manualServeByteRange(response, diskPath, range);
        }
        // Update kickstart session
        if (ksession != null &&
                (!(ksession.getState().getLabel().equals(KickstartSessionState.COMPLETE) ||
                        ksession.getState().getLabel().equals(KickstartSessionState.FAILED)))) {
            ksession.setState(newState);
            if (ksession.getPackageFetchCount() == null) {
                ksession.setPackageFetchCount(0L);
            }
            if (ksession.getState().getLabel().equals(
                    KickstartSessionState.IN_PROGRESS)) {
                log.debug("Incrementing counter.");
                ksession.setPackageFetchCount(
                        ksession.getPackageFetchCount() + 1);
                ksession.setLastFileRequest(path);
            }
            log.debug("Saving session.");
            KickstartFactory.saveKickstartSession(ksession);
        }
        log.debug("returning getStreamForPath");

        File actualFile = new File(diskPath);
        Date mtime = new Date(actualFile.lastModified());
        SimpleDateFormat formatter = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
        formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        setContentInfo(response, actualFile.length(), CONTENT_TYPE_OCTET_STREAM);
        response.addHeader("last-modified", formatter.format(mtime));
        log.debug("added last-modified and content-length values");
        return getStreamForPath(diskPath, CONTENT_TYPE_OCTET_STREAM);
    }

    private void setContentInfo(HttpServletResponse responseIn, long lengthIn,
            String type) {
        responseIn.setContentType(type);
        // do not use setContentLength(), because of it receives only integer value
        responseIn.setHeader("Content-Length", String.valueOf(lengthIn));
    }

    private StreamInfo getStream(byte[] text, String type) {
        return new ByteArrayStreamInfo(type, text);
    }

    private StreamInfo getStreamForPath(String path, String type) {
        File file = new File(path);
        return new FileStreamInfo(type, file);
    }

    private String getNextValue(Iterator<String> it) {
        while (it.hasNext()) {
            String next = it.next();
            if (!StringUtils.isEmpty(next)) {
                return next;
            }
        }
        return null;
    }

    // Ported from perl - needed for proxy support
    private StreamInfo manualServeChecksum(HttpServletResponse response,
            Package rpmPackage, String diskPath) throws IOException {

        response.setContentType(CONTENT_TYPE_OCTET_STREAM);
        String checksum;
        // Obtain the checksum for the file in question and stick it in the
        // outgoing HTTP headers under "X-RHN-Checksum".
        if (rpmPackage != null && rpmPackage.getChecksum() != null && rpmPackage.getChecksum().getChecksum() != null) {
            checksum = rpmPackage.getChecksum().getChecksum();
            response.setHeader("Content-Length", String.valueOf(rpmPackage.getPackageSize()));
        }
        else {
            File f = new File(diskPath);
            if (!f.exists()) {
                log.error("manualServeChecksum :: File not found: {}", diskPath);
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return getStream(new byte[0], CONTENT_TYPE_TEXT_PLAIN);
            }
            checksum = SHA256Crypt.getFileSHA256Sum(f);
            response.setHeader("Content-Length", String.valueOf(f.length()));
        }
        // Create some headers.
        response.addHeader("X-RHN-Checksum", checksum);
        response.setStatus(HttpServletResponse.SC_OK);
        return getStream("".getBytes(), CONTENT_TYPE_TEXT_PLAIN);
    }

    // Ported from perl - needed for yum's requests for byte ranges
    private StreamInfo manualServeByteRange(HttpServletResponse response, String diskPath, String range) {

        // bytes=440-25183
        Pattern rangePattern = Pattern.compile("bytes=(\\d*)-(\\d*)");
        Matcher rangeMatcher = rangePattern.matcher(range);

        if (!rangeMatcher.matches()) {
            // this will fail
            rangeMatcher.group(1);
        }

        long start, end;
        if (StringUtils.isEmpty(rangeMatcher.group(1))) {
            start = 0;
        }
        else {
            start = Long.parseLong(rangeMatcher.group(1));
        }
        File actualFile = new File(diskPath);
        long totalSize = actualFile.length();
        if (StringUtils.isEmpty(rangeMatcher.group(2))) {
            end = totalSize;
        }
        else {
            end = Long.parseLong(rangeMatcher.group(2));
        }
        log.debug("manualServeByteRange Start    : {}", start);
        log.debug("manualServeByteRange End      : {}", end);
        long size = end - start + 1;

        log.debug("manualServeByteRange totalsize: {}", totalSize);

        if (size <= 0) {
            return getStreamForPath(diskPath, CONTENT_TYPE_OCTET_STREAM);
        }
        setContentInfo(response, size, CONTENT_TYPE_OCTET_STREAM);
        response.setStatus(HttpServletResponse.SC_PARTIAL_CONTENT);
        Date mtime = new Date(actualFile.lastModified());
        SimpleDateFormat formatter = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
        formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        String fdate = formatter.format(mtime);
        response.addHeader("last-modified", fdate);
        response.addHeader("Content-Range", "bytes " + start + "-" + end + "/" + totalSize);
        response.addHeader("Accept-Ranges", "bytes");
        log.debug("Added header last-modified: {}", fdate);
        log.debug("Added header Content-Length: {}", size);
        log.debug("Added header Content-Range: bytes {}-{}/{}", start, end, totalSize);
        log.debug("Added header Accept-Ranges: bytes");
        // TODO: it's a bad idea to read file from filesystem into memory.
        // We have to implement copying from InputStream to OutputStream by chunks in this
        // class instead of using parent execute() (and copy()).
        // New copy() method will take into account Content-Range header in response
        // and copy only these bytes. Uncomment after fixing following line:
        // return getStreamForPath(diskPath, CONTENT_TYPE_OCTET_STREAM)

        // gotta make sure it is end + 1
        byte[] chunk = FileUtils.readByteArrayFromFile(actualFile, start, end + 1);
        log.debug("chunk size: {}", chunk.length);
        log.debug("read chunk into byte array.  returning ByteArrayStreamInfo");
        return new ByteArrayStreamInfo(CONTENT_TYPE_OCTET_STREAM, chunk);
    }
}
