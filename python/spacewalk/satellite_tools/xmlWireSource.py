#  pylint: disable=missing-module-docstring,invalid-name
#
# Copyright (c) 2008--2018 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 2 (GPLv2). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
# along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#
# Red Hat trademarks are not licensed under GPLv2. No permission is
# granted to use or replicate Red Hat trademarks that are incorporated
# in this software or its documentation.
#


# pylint: disable=E0012, C0413
# system imports
import os
import sys
import time

# rhn imports
from rhn import rpclib

sys.path.append("/usr/share/rhn")
from up2date_client import config

from uyuni.common.usix import raise_with_tb
from uyuni.common import rhnLib
from spacewalk.common.rhnConfig import CFG

# local imports
from spacewalk.satellite_tools.syncLib import log, log2, RhnSyncException

# pylint: disable-next=reimported,ungrouped-imports
from rhn import rpclib

# pylint: disable-next=ungrouped-imports
from spacewalk.common.suseLib import get_proxy
from spacewalk.satellite_tools import connection


class BaseWireSource:
    """Base object for wire-commo to RHN for delivery of XML/RPMS."""

    serverObj = None
    handler = ""
    url = ""
    sslYN = 0
    systemid = None
    server_handler = None
    xml_dump_version = None

    def __init__(self, systemid, sslYN=0, xml_dump_version=None):
        if not BaseWireSource.systemid:
            BaseWireSource.systemid = systemid
        BaseWireSource.sslYN = sslYN
        BaseWireSource.xml_dump_version = xml_dump_version

    def getServer(self, forcedYN=0):
        if forcedYN:
            self.setServer(self.handler, self.url, forcedYN)
        return BaseWireSource.serverObj

    def schemeAndUrl(self, url):
        """http[s]://BLAHBLAHBLAH/ACKACK --> http[s]://BLAHBLAHBLAH"""

        if not url:
            url = CFG.RHN_PARENT  # the default
        # just make the url complete.
        hostname = rhnLib.parseUrl(url or "")[1]
        hostname = hostname.split(":")[0]  # just in case
        if self.sslYN:
            url = "https://" + hostname
        else:
            url = "http://" + hostname
        return url

    def setServer(self, handler, url=None, forcedYN=0):
        """XMLRPC server object (ssl set in parameters).
        NOTE: url expected to be of the form: scheme://machine/HANDLER
        """

        url = self.schemeAndUrl(url)

        if self._cached_connection_params(handler, url, forcedYN=forcedYN):
            # Already cached
            return

        self._set_connection_params(handler, url)

        # pylint: disable-next=consider-using-f-string
        url = "%s%s" % (url, handler)  # url is properly set up now.

        serverObj = self._set_connection(url)
        self._set_ssl_trusted_certs(serverObj)
        return serverObj

    @staticmethod
    def _set_connection_params(handler, url):
        BaseWireSource.handler = handler
        BaseWireSource.url = url

    def _cached_connection_params(self, handler, url, forcedYN=0):
        """Helper function; returns 0 if we have to reset the connection
        params, 1 if the cached values are ok"""
        if forcedYN:
            return 0
        if handler != self.handler or url != self.url:
            return 0
        return 1

    def _set_connection(self, url):
        "Instantiates a connection object"

        proxy, puser, ppass = get_proxy(url)
        serverObj = connection.StreamConnection(
            url,
            proxy=proxy,
            username=puser,
            password=ppass,
            xml_dump_version=self.xml_dump_version,
            timeout=CFG.timeout,
        )
        BaseWireSource.serverObj = serverObj
        return serverObj

    def _set_ssl_trusted_certs(self, serverObj):
        if not self.sslYN:
            return None

        # Check certificate
        caChain = CFG.CA_CHAIN
        if caChain:
            # require SSL CA file to be able to authenticate the SSL
            # connections.
            if not os.access(caChain, os.R_OK):
                message = (
                    # pylint: disable-next=consider-using-f-string
                    "ERROR: can not find SUSE Multi-Linux Manager CA file: %s"
                    % caChain
                )
                log(-1, message, stream=sys.stderr)
                # pylint: disable-next=broad-exception-raised
                raise Exception(message)
            # force the validation of the SSL cert
            serverObj.add_trusted_cert(caChain)
            return caChain

        message = "--- Warning: SSL connection made but no CA certificate used"
        log(1, message, stream=sys.stderr)
        return None

    def _openSocketStream(self, method, params):
        """Wraps the gzipstream.GzipStream instantiation in a test block so we
        can open normally if stream is not gzipped."""

        stream = None
        retryYN = 0
        wait = 0.33
        lastErrorMsg = ""
        cfg = config.initUp2dateConfig()
        for i in range(cfg["networkRetries"]):
            server = self.getServer(retryYN)
            if server is None:
                log2(
                    -1,
                    2,
                    # pylint: disable-next=consider-using-f-string
                    "ERROR: server unable to initialize, attempt %s" % i,
                    stream=sys.stderr,
                )
                retryYN = 1
                time.sleep(wait)
                continue
            func = getattr(server, method)
            try:
                stream = func(*params)
                if CFG.SYNC_TO_TEMP:
                    # pylint: disable-next=import-outside-toplevel
                    import tempfile

                    cached = tempfile.NamedTemporaryFile()
                    stream.read_to_file(cached)
                    cached.seek(0)
                    return cached
                else:
                    return stream
            except rpclib.xmlrpclib.ProtocolError:
                e = sys.exc_info()[1]
                p = tuple(["<the systemid>"] + list(params[1:]))
                # pylint: disable-next=consider-using-f-string
                lastErrorMsg = "ERROR: server.%s%s: %s" % (method, p, e)
                log2(-1, 2, lastErrorMsg, stream=sys.stderr)
                retryYN = 1
                time.sleep(wait)
                # do not reraise this exception!
            except (KeyboardInterrupt, SystemExit):
                raise
            except rpclib.xmlrpclib.Fault:
                e = sys.exc_info()[1]
                lastErrorMsg = e.faultString
                break
            except Exception:  # pylint: disable=E0012, W0703
                e = sys.exc_info()[1]
                p = tuple(["<the systemid>"] + list(params[1:]))
                # pylint: disable-next=consider-using-f-string
                lastErrorMsg = "ERROR: server.%s%s: %s" % (method, p, e)
                log2(-1, 2, lastErrorMsg, stream=sys.stderr)
                break
                # do not reraise this exception!
        if lastErrorMsg:
            raise_with_tb(RhnSyncException(lastErrorMsg), sys.exc_info()[2])
        # Returns a stream
        # Should never be reached
        return stream

    def setServerHandler(self, isIss=0):
        if isIss:
            self.server_handler = CFG.RHN_ISS_METADATA_HANDLER
        else:
            self.server_handler = CFG.RHN_METADATA_HANDLER


class MetadataWireSource(BaseWireSource):
    """retrieve specific xml stream through xmlrpc interface."""

    @staticmethod
    def is_disk_loader():
        return False

    def _prepare(self):
        self.setServer(self.server_handler)

    def getArchesXmlStream(self):
        """retrieve xml stream for arch data."""
        self._prepare()
        return self._openSocketStream("dump.arches", (self.systemid,))

    def getArchesExtraXmlStream(self):
        "retrieve xml stream for the server group type arch compat"
        self._prepare()
        return self._openSocketStream("dump.arches_extra", (self.systemid,))

    def getProductNamesXmlStream(self):
        "retrieve xml stream for the product names data"
        self._prepare()
        return self._openSocketStream("dump.product_names", (self.systemid,))

    def getChannelFamilyXmlStream(self):
        """retrieve xml stream for channel family data."""
        self._prepare()
        return self._openSocketStream("dump.channel_families", (self.systemid,))

    def getOrgsXmlStream(self):
        """retrieve xml stream for org data."""
        self._prepare()
        return self._openSocketStream("dump.orgs", (self.systemid,))

    def getChannelXmlStream(self):
        """retrieve xml stream for channel data given a
        list of channel labels."""
        self._prepare()
        return self._openSocketStream("dump.channels", (self.systemid, []))

    def getShortPackageXmlStream(self, packageIds):
        """retrieve xml stream for short package data given
        a list of package ids."""
        self._prepare()
        return self._openSocketStream(
            "dump.packages_short", (self.systemid, packageIds)
        )

    def getChannelShortPackagesXmlStream(self, channel, last_modified):
        """retrieve xml stream for short package data given a channel
        label and the last modified timestamp of the channel"""
        self._prepare()
        return self._openSocketStream(
            "dump.channel_packages_short", (self.systemid, channel, last_modified)
        )

    def getPackageXmlStream(self, packageIds):
        """retrieve xml stream for package data given a
        list of package ids."""
        self._prepare()
        return self._openSocketStream("dump.packages", (self.systemid, packageIds))

    def getSourcePackageXmlStream(self, packageIds):
        """retrieve xml stream for package data given a
        list of package ids."""
        self._prepare()
        return self._openSocketStream(
            "dump.source_packages", (self.systemid, packageIds)
        )

    def getErrataXmlStream(self, erratumIds):
        """retrieve xml stream for erratum data given a list of erratum ids."""
        self._prepare()
        return self._openSocketStream("dump.errata", (self.systemid, erratumIds))

    def getKickstartsXmlStream(self, ksLabels):
        "retrieve xml stream for kickstart trees"
        self._prepare()
        return self._openSocketStream(
            "dump.kickstartable_trees", (self.systemid, ksLabels)
        )

    def getComps(self, channel):
        return self._openSocketStream("dump.get_comps", (self.systemid, channel))

    def getModules(self, channel):
        return self._openSocketStream("dump.get_modules", (self.systemid, channel))

    def getRpm(self, nvrea, channel, checksum):
        release = nvrea[2]
        epoch = nvrea[3]
        if epoch:
            # pylint: disable-next=consider-using-f-string
            release = "%s:%s" % (release, epoch)
        # pylint: disable-next=consider-using-f-string
        package_name = "%s-%s-%s.%s.rpm" % (nvrea[0], nvrea[1], release, nvrea[4])
        self._prepare()
        return self._openSocketStream(
            "dump.get_rpm", (self.systemid, package_name, channel, checksum)
        )

    def getKickstartFile(self, ks_label, relative_path):
        self._prepare()
        return self._openSocketStream(
            "dump.get_ks_file", (self.systemid, ks_label, relative_path)
        )

    def getSupportInformationXmlStream(self):
        """retrieve xml stream for channel family data."""
        self._prepare()
        return self._openSocketStream("dump.support_information", (self.systemid,))

    def getSuseProductsXmlStream(self):
        """retrieve xml stream for SUSE Products"""
        self._prepare()
        return self._openSocketStream("dump.suse_products", (self.systemid,))

    def getSuseProductChannelsXmlStream(self):
        """retrieve xml stream for SUSE Product Channels"""
        self._prepare()
        return self._openSocketStream("dump.suse_product_channels", (self.systemid,))

    def getSuseUpgradePathsXmlStream(self):
        """retrieve xml stream for Upgrade Paths"""
        self._prepare()
        return self._openSocketStream("dump.suse_upgrade_paths", (self.systemid,))

    def getSuseProductExtensionsXmlStream(self):
        """retrieve xml stream for SUSE Product Extensions"""
        self._prepare()
        return self._openSocketStream("dump.suse_product_extensions", (self.systemid,))

    def getSuseProductRepositoriesXmlStream(self):
        """retrieve xml stream for SUSE Product Repositories"""
        self._prepare()
        return self._openSocketStream(
            "dump.suse_product_repositories", (self.systemid,)
        )

    def getSCCRepositoriesXmlStream(self):
        """retrieve xml stream for SCC Repositories"""
        self._prepare()
        return self._openSocketStream("dump.scc_repositories", (self.systemid,))

    def getSuseSubscriptionsXmlStream(self):
        """retrieve xml stream for Subscriptions"""
        self._prepare()
        return self._openSocketStream("dump.suse_subscriptions", (self.systemid,))

    def getClonedChannelsXmlStream(self):
        """retrieve xml stream for Cloned Channels"""
        self._prepare()
        return self._openSocketStream("dump.cloned_channels", (self.systemid,))


class XMLRPCWireSource(BaseWireSource):
    "Base class for all the XMLRPC calls"

    @staticmethod
    def _xmlrpc(function, params):
        try:
            retval = getattr(BaseWireSource.serverObj, function)(*params)
        except TypeError:
            e = sys.exc_info()[1]
            log(
                -1,
                # pylint: disable-next=consider-using-f-string
                'ERROR: during "getattr(BaseWireSource.serverObj, %s)(*(%s))"'
                % (function, params),
            )
            raise
        except rpclib.xmlrpclib.ProtocolError:
            e = sys.exc_info()[1]
            # pylint: disable-next=consider-using-f-string
            log2(-1, 2, "ERROR: ProtocolError: %s" % e, stream=sys.stderr)
            raise
        return retval


class AuthWireSource(XMLRPCWireSource):
    """Simply authenticate this systemid as a satellite."""

    def checkAuth(self):
        self.setServer(CFG.RHN_XMLRPC_HANDLER)
        authYN = None
        log(
            2,
            "   +++ SUSE Multi-Linux Manager Server synchronization tool checking in.",
        )
        try:
            authYN = self._xmlrpc("authentication.check", (self.systemid,))
        # pylint: disable-next=try-except-raise
        except (rpclib.xmlrpclib.ProtocolError, rpclib.xmlrpclib.Fault):
            raise
        if authYN:
            log(
                2,
                "   +++ Entitled SUSE Multi-Linux Manager Server validated.",
                stream=sys.stderr,
            )
        elif authYN is None:
            log(
                -1,
                # pylint: disable-next=consider-using-f-string
                "   --- An error occurred upon authentication of this SUSE Multi-Linux Manager Server -- "
                "review the pertinent log file (%s) and/or submit a service request."
                % CFG.LOG_FILE,
                stream=sys.stderr,
            )
            sys.exit(-1)
        elif authYN == 0:
            log(-1, "   --- This server is not entitled.", stream=sys.stderr)
            sys.exit(-1)
        return authYN


class RPCGetWireSource(BaseWireSource):
    "Class to retrieve various files via authenticated GET requests"

    get_server_obj = None
    login_token = None
    get_server_obj = None

    def __init__(self, systemid, sslYN, xml_dump_version):
        BaseWireSource.__init__(self, systemid, sslYN, xml_dump_version)
        self.extinctErrorYN = 0

    @staticmethod
    def _set_connection_params(handler, url):
        BaseWireSource._set_connection_params(handler, url)
        RPCGetWireSource.login_token = None

    def login(self, force=0):
        "Perform a login, return a GET Server instance"
        if force:
            # Invalidate it
            self._set_login_token(None)
        if self.login_token:
            # Return cached one
            return self.get_server_obj

        # Force a login otherwise
        self._set_login_token(self._login())
        url = self.url + self.handler
        proxy, puser, ppass = get_proxy(url)
        get_server_obj = connection.GETServer(
            url,
            proxy=proxy,
            username=puser,
            password=ppass,
            headers=self.login_token,
            timeout=CFG.timeout,
        )
        # Add SSL trusted cert
        self._set_ssl_trusted_certs(get_server_obj)
        self._set_rpc_server(get_server_obj)
        return self.get_server_obj

    def _login(self):
        if not self.systemid:
            # pylint: disable-next=broad-exception-raised
            raise Exception("systemid not set!")

        # Set the URL to the one for regular XML-RPC calls
        self.setServer(CFG.RHN_XMLRPC_HANDLER)

        try:
            login_token = self.getServer().authentication.login(self.systemid)
        except rpclib.xmlrpclib.ProtocolError:
            e = sys.exc_info()[1]
            # pylint: disable-next=consider-using-f-string
            log2(-1, 2, "ERROR: ProtocolError: %s" % e, stream=sys.stderr)
            raise
        return login_token

    @staticmethod
    def _set_login_token(token):
        RPCGetWireSource.login_token = token

    @staticmethod
    def _set_rpc_server(server):
        RPCGetWireSource.get_server_obj = server

    def _rpc_call(self, function_name, params):
        get_server_obj = self.login()
        # Try a couple of times
        fault_count = 0
        expired_token = 0
        cfg = config.initUp2dateConfig()
        while fault_count - expired_token < cfg["networkRetries"]:
            try:
                ret = getattr(get_server_obj, function_name)(*params)
            except rpclib.xmlrpclib.ProtocolError:
                e = sys.exc_info()[1]
                # We have two codes to check: the HTTP error code, and the
                # combination (failtCode, faultString) encoded in the headers
                # of the request.
                http_error_code = e.errcode
                fault_code, fault_string = rpclib.reportError(e.headers)
                fault_count += 1
                if http_error_code == 401 and fault_code == -34:
                    # Login token expired
                    get_server_obj = self.login(force=1)
                    # allow exactly one respin for expired token
                    expired_token = 1
                    continue
                if http_error_code == 404 and fault_code == -17:
                    # File not found
                    self.extinctErrorYN = 1
                    return None
                log(
                    -1,
                    # pylint: disable-next=consider-using-f-string
                    "ERROR: http error code :%s; fault code: %s; %s"
                    % (http_error_code, fault_code, fault_string),
                )
                # XXX
                raise
            else:
                return ret
        # pylint: disable-next=broad-exception-raised
        raise Exception("Failed after multiple attempts!")

    def getPackageStream(self, channel, nvrea, checksum):
        release = nvrea[2]
        epoch = nvrea[3]
        if epoch:
            # pylint: disable-next=consider-using-f-string
            release = "%s:%s" % (release, epoch)
        # pylint: disable-next=consider-using-f-string
        package_name = "%s-%s-%s.%s.rpm" % (nvrea[0], nvrea[1], release, nvrea[4])
        return self._rpc_call("getPackage", (channel, package_name, checksum))

    def getKickstartFileStream(self, channel, ks_tree_label, relative_path):
        return self._rpc_call(
            "getKickstartFile", (channel, ks_tree_label, relative_path)
        )

    def getCompsFileStream(self, channel):
        return self._rpc_call("repodata", (channel, "comps.xml"))

    def getModulesFilesStram(self, channel):
        return self._rpc_call("repodata", (channel, "modules.yaml"))
