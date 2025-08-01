#  pylint: disable=missing-module-docstring
# coding: utf-8
#
# Copyright (c) 2008--2018 Red Hat, Inc.
# Copyright (c) 2010--2019 SUSE LINUX GmbH, Nuernberg, Germany.
#
# This software is licensed to you under the GNU General Public License,
# version 2 (GPLv2). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
# along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#
# SUSE trademarks are not licensed under GPLv2. No permission is
# granted to use or replicate SUSE trademarks that are incorporated
# in this software or its documentation.
#
# Red Hat trademarks are not licensed under GPLv2. No permission is
# granted to use or replicate Red Hat trademarks that are incorporated
# in this software or its documentation.
#

from __future__ import absolute_import, unicode_literals

# pylint: disable-next=unused-import
from shutil import rmtree, copytree

import configparser
import fnmatch

# pylint: disable-next=unused-import
import glob

# pylint: disable-next=unused-import
import gzip

# pylint: disable-next=unused-import
import bz2

# pylint: disable-next=unused-import
import lzma
import os
import re
import solv
import subprocess
import sys
import tempfile
import traceback

# pylint: disable-next=unused-import
import types
import urlgrabber
import looseversion
import json

try:
    from urllib import urlencode, unquote, quote
    from urlparse import urlsplit, urlparse, urlunparse
# pylint: disable-next=bare-except
except:
    from urllib.parse import urlsplit, urlencode, urlparse, urlunparse, unquote, quote

import xml.etree.ElementTree as etree

from functools import cmp_to_key
from shlex import quote as sh_quote
from uyuni.common import checksum, fileutils
from spacewalk.common import rhnLog
from spacewalk.satellite_tools.repo_plugins import ContentPackage, CACHE_DIR
from spacewalk.satellite_tools.download import get_proxies
from spacewalk.satellite_tools.syncLib import log

# pylint: disable-next=unused-import
from spacewalk.common.rhnConfig import cfg_component
from spacewalk.common.suseLib import get_proxy, URL as suseLibURL, get_content_type
from rhn.stringutils import sstr
from urlgrabber.grabber import URLGrabError
from urlgrabber.mirror import MirrorGroup


# namespace prefix to parse patches.xml file
PATCHES_XML = "{http://novell.com/package/metadata/suse/patches}"
REPO_XML = "{http://linux.duke.edu/metadata/repo}"
METALINK_XML = "{http://www.metalinker.org/}"

CACHE_DIR = "/var/cache/rhn/reposync"
SPACEWALK_LIB = "/var/lib/spacewalk"
SPACEWALK_GPG_KEYRING = os.path.join(SPACEWALK_LIB, "gpgdir/pubring.gpg")
ZYPP_CACHE_PATH = "var/cache/zypp"
ZYPP_RAW_CACHE_PATH = os.path.join(ZYPP_CACHE_PATH, "raw")
ZYPP_SOLV_CACHE_PATH = os.path.join(ZYPP_CACHE_PATH, "solv")
REPOSYNC_ZYPPER_ROOT = os.path.join(SPACEWALK_LIB, "reposync/root")
REPOSYNC_ZYPPER_RPMDB_PATH = os.path.join(REPOSYNC_ZYPPER_ROOT, "var/lib/rpm")
REPOSYNC_ZYPPER_CONF = "/etc/rhn/spacewalk-repo-sync/zypper.conf"
REPOSYNC_EXTRA_HTTP_HEADERS_CONF = "/etc/rhn/spacewalk-repo-sync/extra_headers.conf"

RPM_PUBKEY_VERSION_RELEASE_RE = re.compile(r"^gpg-pubkey-([0-9a-fA-F]+)-([0-9a-fA-F]+)")

# possible urlgrabber errno
NO_MORE_MIRRORS_TO_TRY = 256


class ZyppoSync:
    """
    This class prepares a environment for running Zypper inside a dedicated reposync root

    """

    def __init__(self, root=None):
        self._root = root
        if self._root is not None:
            self._init_root(self._root)

    def _init_root(self, root):
        """
        Creates a root environment for Zypper, but only if none is around.

        :return: None
        """
        try:
            for pth in [
                root,
                os.path.join(root, "etc/zypp/repos.d"),
                REPOSYNC_ZYPPER_ROOT,
            ]:
                if not os.path.exists(pth):
                    os.makedirs(pth)
        except Exception as exc:
            # pylint: disable-next=consider-using-f-string
            msg = "Unable to initialise Zypper root for {}: {}".format(root, exc)
            rhnLog.log_clean(0, msg)
            sys.stderr.write(str(msg) + "\n")
            raise
        try:
            # Synchronize new GPG keys that come from the Spacewalk GPG keyring
            self.__synchronize_gpg_keys()
        # pylint: disable-next=broad-exception-caught
        except Exception as exc:
            # pylint: disable-next=consider-using-f-string
            msg = "Unable to synchronize Spacewalk GPG keyring: {}".format(exc)
            rhnLog.log_clean(0, msg)
            sys.stderr.write(str(msg) + "\n")

    def __synchronize_gpg_keys(self):
        """
        This method does update the Zypper RPM database with new keys coming from the Spacewalk GPG keyring

        """

        def _log_command(args):
            log(3, " ".join([sh_quote(x) for x in args]))

        spacewalk_gpg_keys = {}
        zypper_gpg_keys = {}

        with tempfile.TemporaryDirectory() as temp_dir:
            # Collect GPG keys from the Spacewalk GPG keyring
            # The '--export-options export-clean' is needed avoid exporting key signatures
            # which are not needed and can cause issues when importing into the RPMDB
            all_keys_file = os.path.join(temp_dir, "_all_keys.gpg")
            args = [
                "/usr/bin/gpg",
                "-q",
                "--batch",
                "--no-options",
                "--no-default-keyring",
                "--no-permission-warning",
                "--keyring",
                SPACEWALK_GPG_KEYRING,
                "--export",
                "--export-options",
                "export-clean",
                "--with-colons",
                "-a",
                "--output",
                all_keys_file,
            ]
            _log_command(args)
            process = subprocess.run(args, check=False)
            args = [
                "gpg",
                "--verbose",
                "--with-colons",
                all_keys_file,
            ]
            _log_command(args)
            process = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            for line in process.stdout.readlines():
                line_l = line.decode().split(":")
                if line_l[0] == "sig" and "selfsig" in line_l[10]:
                    spacewalk_gpg_keys.setdefault(line_l[4][8:].lower(), []).append(
                        format(int(line_l[5]), "x")
                    )
            log(
                3,
                # pylint: disable-next=consider-using-f-string
                "spacewalk keyIds: {}".format([k for k in sorted(spacewalk_gpg_keys)]),
            )

            # Collect GPG keys from reposync Zypper RPM database
            args = [
                "/usr/bin/rpm",
                "-q",
                "gpg-pubkey",
                "--dbpath",
                REPOSYNC_ZYPPER_RPMDB_PATH,
            ]
            _log_command(args)
            process = subprocess.Popen(args, stdout=subprocess.PIPE)
            for line in process.stdout.readlines():
                match = RPM_PUBKEY_VERSION_RELEASE_RE.match(line.decode())
                if match:
                    zypper_gpg_keys[match.groups()[0]] = match.groups()[1]
            # pylint: disable-next=consider-using-f-string
            log(3, "zypper keyIds:    {}".format(sorted(zypper_gpg_keys.keys())))

            keys_to_load = list(
                set(spacewalk_gpg_keys).difference(set(zypper_gpg_keys))
            )
            # pylint: disable-next=consider-using-f-string
            log(3, "diff keyIds:      {}".format(keys_to_load))

            # Compare GPG keys and remove keys from reposync that are going to be imported with a newer release.
            # pylint: disable-next=consider-using-dict-items
            for key in zypper_gpg_keys:
                # If the GPG key id already exists, is that new key actually newer? We need to check the release
                release_i = int(zypper_gpg_keys[key], 16)
                if key in spacewalk_gpg_keys and any(
                    int(i, 16) > release_i for i in spacewalk_gpg_keys[key]
                ):
                    # This GPG key has a newer release on the Spacewalk GPG keyring that on the reposync Zypper RPM database.
                    # We delete this key from the RPM database to allow importing the newer version.
                    args = [
                        "/usr/bin/rpm",
                        "-q",
                        "--dbpath",
                        REPOSYNC_ZYPPER_RPMDB_PATH,
                        "-e",
                        # pylint: disable-next=consider-using-f-string
                        "gpg-pubkey-{}-{}".format(key, zypper_gpg_keys[key]),
                    ]
                    _log_command(args)
                    subprocess.run(args, check=False)
                    log(
                        3,
                        # pylint: disable-next=consider-using-f-string
                        "New version available for gpg-pubkey-{}-{}".format(
                            key, zypper_gpg_keys[key]
                        ),
                    )
                    keys_to_load.append(key)

            # pylint: disable-next=consider-using-f-string
            log(3, "to load keyIds:   {}".format(keys_to_load))

            # Finally, once we deleted the existing old key releases from the Zypper RPM database
            # we proceed to import all missing keys from the Spacewalk GPG keyring. This will allow new GPG
            # keys release are upgraded in the Zypper keyring since rpmkeys does not handle the upgrade
            # properly
            for key_id in keys_to_load:
                # pylint: disable-next=consider-using-f-string
                key_file = os.path.join(temp_dir, "{}.gpg".format(key_id))
                args = [
                    "/usr/bin/gpg",
                    "-q",
                    "--batch",
                    "--no-options",
                    "--no-default-keyring",
                    "--no-permission-warning",
                    "--keyring",
                    SPACEWALK_GPG_KEYRING,
                    "--export",
                    "--export-options",
                    "export-clean",
                    "--with-colons",
                    "-a",
                    "--output",
                    key_file,
                    key_id,
                ]
                _log_command(args)
                subprocess.run(args, check=False)
                args = [
                    "/usr/bin/rpmkeys",
                    "-vv",
                    "--dbpath",
                    REPOSYNC_ZYPPER_RPMDB_PATH,
                    "--import",
                    key_file,
                ]
                _log_command(args)
                process = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                )
                try:
                    outs, _ = process.communicate(timeout=15)
                    if process.returncode is None or process.returncode > 0:
                        log(
                            0,
                            # pylint: disable-next=consider-using-f-string
                            "Failed to import key {} into rpm database, rpmkeys returned ({}): {}".format(
                                key_id, process.returncode, outs.decode("utf-8")
                            ),
                        )
                except subprocess.TimeoutExpired:
                    process.kill()
                    log(0, "Timeout exceeded while importing keys to rpm database")


# pylint: disable-next=missing-class-docstring
class ZypperRepo:
    def __init__(self, root, url, org):
        self.root = root
        self.baseurl = [url]
        self.basecachedir = os.path.join(CACHE_DIR, org)
        # pylint: disable-next=redefined-outer-name,invalid-name
        with cfg_component("server.satellite") as CFG:
            self.pkgdir = os.path.join(CFG.MOUNT_POINT, CFG.PREPENDED_DIR, org, "stage")
        self.urls = self.baseurl
        # Make sure baseurl ends with / and urljoin will work correctly
        if self.urls[0][-1] != "/":
            self.urls[0] += "/"
        # Make sure root paths are created
        # pylint: disable-next=invalid-name
        with cfg_component(component=None) as CFG:
            if not os.path.isdir(self.root):
                fileutils.makedirs(self.root, user="root", group="root", mode=0o0600)
            else:
                os.chmod(self.root, mode=0o0600)
            if not os.path.isdir(self.pkgdir):
                fileutils.makedirs(
                    self.pkgdir, user=CFG.httpd_user, group=CFG.httpd_group
                )
        self.is_configured = False
        self.includepkgs = []
        self.exclude = []


# pylint: disable-next=missing-class-docstring
class RawSolvablePackage:
    def __init__(self, solvable):
        self.name = solvable.name
        self.raw_name = str(solvable)
        self.epoch, self.version, self.release = self._parse_solvable_evr(solvable.evr)
        self.arch = solvable.arch
        cksum = solvable.lookup_checksum(solv.SOLVABLE_CHECKSUM)
        self.checksum_type = cksum.typestr()
        self.checksum = cksum.hex()
        self.packagesize = solvable.lookup_num(solv.SOLVABLE_DOWNLOADSIZE)
        self.relativepath = solvable.lookup_location()[0]

    def __repr__(self):
        # pylint: disable-next=consider-using-f-string
        return "RawSolvablePackage({})".format(self.raw_name)

    @staticmethod
    def _parse_solvable_evr(evr):
        """
        Return the (epoch, version, release) tuple based on evr string.
        The "evr" string from libsolv is represented as: "epoch:version-release"

        https://github.com/openSUSE/libsolv/blob/master/src/solvable.h

        :returns: tuple
        """
        if evr in [None, ""]:
            return ("", "", "")
        idx_epoch = evr.find(":")
        epoch = evr[:idx_epoch] if idx_epoch != -1 else ""
        idx_release = evr.find("-")
        if idx_release != -1:
            version = evr[idx_epoch + 1 : idx_release]
            release = evr[idx_release + 1 :]
        else:
            version = evr[idx_epoch + 1 :]
            release = ""
        return epoch, version, release


class RepoMDError(Exception):
    """An exception thrown when not RepoMD is found."""

    pass


class SolvFileNotFound(Exception):
    """An exception thrown when not Solv file is found."""

    pass


class UpdateNoticeException(Exception):
    """An exception thrown for bad UpdateNotice data."""

    pass


class UpdateNotice(object):
    """
    Simplified UpdateNotice class implementation
    https://github.com/rpm-software-management/yum/blob/master/yum/update_md.py

    A single update notice (for instance, a security fix).
    """

    # pylint: disable-next=unused-argument
    def __init__(self, elem=None, repoid=None, vlogger=None):
        self._md = {
            "from": "",
            "type": "",
            "title": "",
            "release": "",
            "status": "",
            "version": "",
            "pushcount": "",
            "update_id": "",
            "issued": "",
            "updated": "",
            "description": "",
            "rights": "",
            "severity": "",
            "summary": "",
            "solution": "",
            "references": [],
            "pkglist": [],
            "reboot_suggested": False,
            "restart_suggested": False,
        }

        if elem is not None:
            self._parse(elem)

    def __getitem__(self, item):
        """Allows scriptable metadata access (ie: un['update_id'])."""
        # pylint: disable-next=unidiomatic-typecheck
        if type(item) is int:
            return sorted(self._md)[item]
        ret = self._md.get(item)
        if ret == "":
            ret = None
        return ret

    def __setitem__(self, item, val):
        self._md[item] = val

    def _parse(self, elem):
        """
        Parse an update element::
            <!ELEMENT update (id, synopsis?, issued, updated,
                              references, description, rights?,
                              severity?, summary?, solution?, pkglist)>
                <!ATTLIST update type (errata|security) "errata">
                <!ATTLIST update status (final|testing) "final">
                <!ATTLIST update version CDATA #REQUIRED>
                <!ATTLIST update from CDATA #REQUIRED>
        """
        if elem.tag == "update":
            for attrib in ("from", "type", "status", "version"):
                self._md[attrib] = elem.attrib.get(attrib)
            if self._md["version"] is None:
                self._md["version"] = "0"
            for child in elem:
                if child.tag == "id":
                    if not child.text:
                        raise UpdateNoticeException("No id element found")
                    self._md["update_id"] = child.text
                elif child.tag == "pushcount":
                    self._md["pushcount"] = child.text
                elif child.tag == "issued":
                    self._md["issued"] = child.attrib.get("date")
                elif child.tag == "updated":
                    self._md["updated"] = child.attrib.get("date")
                elif child.tag == "references":
                    self._parse_references(child)
                elif child.tag == "description":
                    self._md["description"] = child.text
                elif child.tag == "rights":
                    self._md["rights"] = child.text
                elif child.tag == "severity":
                    self._md[child.tag] = child.text
                elif child.tag == "summary":
                    self._md["summary"] = child.text
                elif child.tag == "solution":
                    self._md["solution"] = child.text
                elif child.tag == "pkglist":
                    self._parse_pkglist(child)
                elif child.tag == "title":
                    self._md["title"] = child.text
                elif child.tag == "release":
                    self._md["release"] = child.text
        else:
            raise UpdateNoticeException("No update element found")

    def _parse_references(self, elem):
        """
        Parse the update references::
            <!ELEMENT references (reference*)>
            <!ELEMENT reference>
                <!ATTLIST reference href CDATA #REQUIRED>
                <!ATTLIST reference type (self|other|cve|bugzilla) "self">
                <!ATTLIST reference id CDATA #IMPLIED>
                <!ATTLIST reference title CDATA #IMPLIED>
        """
        for reference in elem:
            if reference.tag == "reference":
                data = {}
                for refattrib in ("id", "href", "type", "title"):
                    data[refattrib] = reference.attrib.get(refattrib)
                self._md["references"].append(data)
            else:
                raise UpdateNoticeException("No reference element found")

    def _parse_pkglist(self, elem):
        """
        Parse the package list::
            <!ELEMENT pkglist (collection+)>
            <!ELEMENT collection (name?, package+)>
                <!ATTLIST collection short CDATA #IMPLIED>
                <!ATTLIST collection name CDATA #IMPLIED>
            <!ELEMENT name (#PCDATA)>
        """
        for collection in elem:
            data = {"packages": []}
            if "short" in collection.attrib:
                data["short"] = collection.attrib.get("short")
            for item in collection:
                if item.tag == "name":
                    data["name"] = item.text
                elif item.tag == "package":
                    data["packages"].append(self._parse_package(item))
            self._md["pkglist"].append(data)

    def _parse_package(self, elem):
        """
        Parse an individual package::
            <!ELEMENT package (filename, sum, reboot_suggested, restart_suggested)>
                <!ATTLIST package name CDATA #REQUIRED>
                <!ATTLIST package version CDATA #REQUIRED>
                <!ATTLIST package release CDATA #REQUIRED>
                <!ATTLIST package arch CDATA #REQUIRED>
                <!ATTLIST package epoch CDATA #REQUIRED>
                <!ATTLIST package src CDATA #REQUIRED>
            <!ELEMENT reboot_suggested (#PCDATA)>
            <!ELEMENT restart_suggested (#PCDATA)>
            <!ELEMENT filename (#PCDATA)>
            <!ELEMENT sum (#PCDATA)>
                <!ATTLIST sum type (md5|sha1) "sha1">
        """
        package = {}
        for pkgfield in ("arch", "epoch", "name", "version", "release", "src"):
            package[pkgfield] = elem.attrib.get(pkgfield)

        #  Bad epoch and arch data is the most common (missed) screwups.
        # Deal with bad epoch data.
        if not package["epoch"] or package["epoch"][0] not in "0123456789":
            package["epoch"] = None

        for child in elem:
            if child.tag == "filename":
                package["filename"] = child.text
            elif child.tag == "sum":
                package["sum"] = (child.attrib.get("type"), child.text)
            elif child.tag == "reboot_suggested":
                self._md["reboot_suggested"] = True
            elif child.tag == "restart_suggested":
                self._md["restart_suggested"] = True
        return package


# pylint: disable-next=missing-class-docstring
class ContentSource:
    # pylint: disable-next=dangerous-default-value
    def __init__(
        self,
        url,
        name,
        insecure=False,
        interactive=True,
        yumsrc_conf=None,
        org="1",
        channel_label="",
        no_mirrors=False,
        ca_cert_file=None,
        client_cert_file=None,
        client_key_file=None,
        channel_arch="",
        http_headers={},
    ):
        """
        Plugin constructor.
        """

        # pylint: disable=W0613
        if urlsplit(url).scheme:
            self.url = url
        else:
            # pylint: disable-next=consider-using-f-string
            self.url = "file://%s" % url
        self.name = name
        self.insecure = insecure
        self.interactive = interactive
        self.org = org if org else "NULL"
        self.proxy_hostname = None
        self.proxy_url = None
        self.proxy_user = None
        self.proxy_pass = None
        self.authtoken = None
        self.sslcacert = ca_cert_file
        self.sslclientcert = client_cert_file
        self.sslclientkey = client_key_file
        self.http_headers = http_headers

        # keep authtokens for mirroring
        # pylint: disable-next=invalid-name,unused-variable
        (_scheme, _netloc, _path, query, _fragid) = urlsplit(url)
        if query:
            self.authtoken = query

        # load proxy configuration based on the url
        self._load_proxy_settings(self.url)

        # Get extra HTTP headers configuration from /etc/rhn/spacewalk-repo-sync/extra_headers.conf
        if os.path.isfile(REPOSYNC_EXTRA_HTTP_HEADERS_CONF):
            http_headers_cfg = configparser.ConfigParser()
            # pylint: disable-next=unspecified-encoding
            http_headers_cfg.read_file(open(REPOSYNC_EXTRA_HTTP_HEADERS_CONF))
            section_name = None

            if http_headers_cfg.has_section(self.name):
                section_name = self.name
            elif http_headers_cfg.has_section(channel_label):
                section_name = channel_label
            elif http_headers_cfg.has_section("main"):
                section_name = "main"

            if section_name:
                for hdr in http_headers_cfg[section_name]:
                    self.http_headers[hdr] = http_headers_cfg.get(
                        section_name, option=hdr
                    )

        # perform authentication if implemented
        self._authenticate(url)

        # Make sure baseurl ends with / and urljoin will work correctly
        self.urls = [url]
        if self.urls[0][-1] != "/":
            self.urls[0] += "/"

        # Replace non-valid characters from reponame (only alphanumeric chars allowed)
        self.reponame = "".join([x if x.isalnum() else "_" for x in self.name])
        self.channel_label = channel_label
        self.channel_arch = channel_arch

        # SUSE vendor repositories belongs to org = NULL
        # The repository cache root will be "/var/cache/rhn/reposync/REPOSITORY_LABEL/"
        root = os.path.join(CACHE_DIR, str(org or "NULL"), self.reponame)

        self.repo = ZypperRepo(root=root, url=self.url, org=self.org)
        self.num_packages = 0
        self.num_excluded = 0
        self.gpgkey_autotrust = None
        self.groupsfile = None

        # pylint: disable-next=redefined-outer-name,invalid-name
        with cfg_component("server.satellite") as CFG:
            # configure network connection
            try:
                # bytes per second
                self.minrate = int(CFG.REPOSYNC_MINRATE)
            except ValueError:
                self.minrate = 1000
            try:
                # seconds
                self.timeout = int(CFG.REPOSYNC_TIMEOUT)
            except ValueError:
                self.timeout = 300
            try:
                # extended reposync nevra filter enable
                # this will filter packages based on full nevra
                # instead of package name only.
                self.nevra_filter = bool(CFG.REPOSYNC_NEVRA_FILTER)
            except (AttributeError, ValueError):
                self.nevra_filter = False

    def _load_proxy_settings(self, url):
        # read the proxy configuration in /etc/rhn/rhn.conf
        # pylint: disable-next=redefined-outer-name,invalid-name
        with cfg_component("server.satellite") as CFG:
            # Get the global HTTP Proxy settings from DB or per-repo
            # settings on /etc/rhn/spacewalk-repo-sync/zypper.conf
            if CFG.http_proxy:
                self.proxy_url, self.proxy_user, self.proxy_pass = get_proxy(url)
                self.proxy_hostname = self.proxy_url
            elif os.path.isfile(REPOSYNC_ZYPPER_CONF):
                zypper_cfg = configparser.ConfigParser()
                # pylint: disable-next=unspecified-encoding
                zypper_cfg.read_file(open(REPOSYNC_ZYPPER_CONF))
                section_name = None

                if zypper_cfg.has_section(self.name):
                    section_name = self.name
                # pylint: disable-next=undefined-variable
                elif zypper_cfg.has_section(channel_label):
                    # pylint: disable-next=undefined-variable
                    section_name = channel_label
                elif zypper_cfg.has_section("main"):
                    section_name = "main"

                if section_name:
                    if zypper_cfg.has_option(section_name, option="proxy"):
                        self.proxy_hostname = zypper_cfg.get(
                            section_name, option="proxy"
                        )
                        # pylint: disable-next=consider-using-f-string
                        self.proxy_url = "http://%s" % self.proxy_hostname

                    if zypper_cfg.has_option(section_name, "proxy_username"):
                        self.proxy_user = zypper_cfg.get(section_name, "proxy_username")

                    if zypper_cfg.has_option(section_name, "proxy_password"):
                        self.proxy_pass = zypper_cfg.get(section_name, "proxy_password")

    def _get_mirror_list(self, repo, url):
        returnlist = []
        content = []
        if url.startswith("file:/"):
            return returnlist

        mirrorlist_path = os.path.join(repo.root, "mirrorlist.txt")
        # If page not plaintext or xml, is not a valid mirrorlist or metalink,
        # so continue without it.
        proxies = get_proxies(self.proxy_url, self.proxy_user, self.proxy_pass)

        content_type = get_content_type(
            url,
            certfile=self.sslclientcert,
            keyfile=self.sslclientkey,
            cafile=self.sslcacert,
            proxies=proxies,
            headers=self.http_headers,
        )
        if (
            "text/plain" not in content_type
            and "xml" not in content_type
            and "octet-stream" not in content_type
        ):
            # Not a valid mirrorlist or metalink; continue without it
            return returnlist

        try:
            urlgrabber_opts = {}
            self.set_download_parameters(urlgrabber_opts, url, mirrorlist_path)
            urlgrabber.urlgrab(url, mirrorlist_path, **urlgrabber_opts)
        except URLGrabError as exc:
            repl_url = suseLibURL(url).getURL(stripPw=True)
            if not hasattr(exc, "code") and exc.errno != 2:
                # pylint: disable-next=consider-using-f-string
                msg = "ERROR: Mirror list download failed: %s - %s" % (
                    url,
                    exc.strerror,
                )
                msg = msg.replace(url, repl_url)
                log(0, msg)
            if rhnLog.LOG and rhnLog.LOG.level >= 1:
                # pylint: disable-next=consider-using-f-string
                msg = "DEBUG[%s/%s]: Mirror list download failed: %s - %s%s" % (
                    exc.errno,
                    exc.code if hasattr(exc, "code") else "-",
                    url,
                    exc.strerror,
                    # pylint: disable-next=consider-using-f-string
                    ": %s" % (traceback.format_exc()) if rhnLog.LOG.level >= 2 else "",
                )
                msg = msg.replace(url, repl_url)
                log(0, msg)
            # no mirror list or metalink found continue without
            return returnlist

        def _replace_and_check_url(url_list):
            goodurls = []
            # pylint: disable-next=unused-variable
            skipped = None
            for url in url_list:
                # obvious bogons get ignored
                if url in ["", None]:
                    continue
                # Discard any urls containing some invalid characters
                forbidden_characters = "<>^`{|}"
                # pylint: disable-next=superfluous-parens
                url_is_invalid = [x for x in forbidden_characters if (x in url)]
                if url_is_invalid:
                    # pylint: disable-next=consider-using-f-string
                    self.error_msg("Discarding invalid url: {}".format(url))
                    continue
                try:
                    # This started throwing ValueErrors, BZ 666826
                    (s, b, p, q, f, o) = urlparse(url)
                    if p[-1] != "/":
                        p = p + "/"
                # pylint: disable-next=unused-variable
                except (ValueError, IndexError, KeyError) as e:
                    s = "blah"

                if s not in ["http", "ftp", "file", "https"]:
                    skipped = url
                    continue
                else:
                    goodurls.append(urlunparse((s, b, p, q, f, o)))
            return goodurls

        try:
            # pylint: disable-next=unspecified-encoding
            with open(mirrorlist_path, "r") as mirrorlist_file:
                content = mirrorlist_file.readlines()
        # pylint: disable-next=broad-exception-caught
        except Exception as exc:
            # pylint: disable-next=consider-using-f-string
            self.error_msg("Could not read mirrorlist: {}".format(exc))

        try:
            # Try to read a metalink XML
            for files in etree.parse(mirrorlist_path).getroot():
                file_elem = files.find(METALINK_XML + "file")
                if file_elem.get("name") == "repomd.xml":
                    # pylint: disable-next=invalid-name
                    _urls = file_elem.find(METALINK_XML + "resources").findall(
                        METALINK_XML + "url"
                    )
                    # pylint: disable-next=invalid-name
                    for _url in _urls:
                        # The mirror urls in the metalink file are for repomd.xml so it
                        # gives a list of mirrors for that one file, but we want the list
                        # of mirror baseurls. Joy of reusing other people's stds. :)
                        if not _url.text.endswith("/repodata/repomd.xml"):
                            continue
                        returnlist.append(_url.text[: -len("/repodata/repomd.xml")])
        # pylint: disable-next=broad-exception-caught
        except Exception as exc:
            # If no metalink XML, we try to read a mirrorlist
            for line in content:
                # pylint: disable-next=anomalous-backslash-in-string
                if re.match("^\s*\#.*", line) or re.match("^\s*$", line):
                    continue
                mirror = re.sub("\n$", "", line)  # no more trailing \n's
                mirror = re.sub(
                    # pylint: disable-next=anomalous-backslash-in-string
                    "\$(?:BASE)?ARCH",
                    self.channel_arch,
                    mirror,
                    flags=re.IGNORECASE,
                )
                returnlist.append(mirror)

        returnlist = _replace_and_check_url(returnlist)

        returnlist = [self._prep_zypp_repo_url(url, False) for url in returnlist]

        try:
            # Write the final mirrorlist that is going to be pass to Zypper
            # pylint: disable-next=unspecified-encoding
            with open(mirrorlist_path, "w") as mirrorlist_file:
                mirrorlist_file.write(os.linesep.join(returnlist))
        # pylint: disable-next=broad-exception-caught
        except Exception as exc:
            # pylint: disable-next=consider-using-f-string
            self.error_msg("Could not write the calculated mirrorlist: {}".format(exc))
        return returnlist

    def setup_repo(self, repo, uln_repo=False):
        """
        Setup repository and fetch metadata
        """
        plugin_used = False
        self.zypposync = ZyppoSync(root=repo.root)
        zypp_repo_url = self._prep_zypp_repo_url(self.url, uln_repo)

        mirrorlist = self._get_mirror_list(repo, self.url)
        if mirrorlist:
            repo.baseurl = mirrorlist
        repo.urls = repo.baseurl

        # Manually call Zypper
        repo_cfg = """[{reponame}]
enabled=1
autorefresh=0
{repo_url}={url}
gpgcheck={gpgcheck}
repo_gpgcheck={gpgcheck}
type=rpm-md
"""
        if uln_repo:
            # pylint: disable-next=invalid-name,consider-using-f-string
            _url = "plugin:spacewalk-uln-resolver?url={}".format(zypp_repo_url)
            plugin_used = True
        elif self.http_headers:
            headers_location = os.path.join(
                repo.root,
                "etc/zypp/repos.d",
                str(self.channel_label or self.reponame) + ".headers",
            )
            # pylint: disable-next=unspecified-encoding
            with open(headers_location, "w") as repo_headers_file:
                repo_headers_file.write(json.dumps(self.http_headers))
            # RHUI mirror url works only as mirror and cannot be used to download content
            # but zypp plugins do not work with "mirrorlist" keyword, only with baseurl.
            # So let's take the first url from the mirrorlist if it exists and use it as baseurl
            baseurl = mirrorlist[0] if mirrorlist else zypp_repo_url
            # pylint: disable-next=invalid-name,consider-using-f-string
            _url = "plugin:spacewalk-extra-http-headers?url={}&headers_file={}".format(
                quote(baseurl), quote(headers_location)
            )
            plugin_used = True
        else:
            # pylint: disable-next=invalid-name
            _url = (
                zypp_repo_url
                if not mirrorlist
                else os.path.join(repo.root, "mirrorlist.txt")
            )

        # pylint: disable-next=unspecified-encoding
        with open(
            os.path.join(
                repo.root,
                "etc/zypp/repos.d",
                str(self.channel_label or self.reponame) + ".repo",
            ),
            "w",
        ) as repo_conf_file:
            # pylint: disable-next=invalid-name
            _repo_url = "baseurl"
            if mirrorlist and not plugin_used:
                # pylint: disable-next=invalid-name
                _repo_url = "mirrorlist"
            repo_conf_file.write(
                repo_cfg.format(
                    reponame=self.channel_label or self.reponame,
                    repo_url=_repo_url,
                    url=_url,
                    gpgcheck="0" if self.insecure else "1",
                )
            )
        zypper_cmd = "zypper"
        if not self.interactive:
            # pylint: disable-next=consider-using-f-string
            zypper_cmd = "{} -n".format(zypper_cmd)
        # pylint: disable-next=consider-using-f-string
        zypper_cmd = "{} --root {} --reposd-dir {} --cache-dir {} --raw-cache-dir {} --solv-cache-dir {} ref".format(
            zypper_cmd,
            REPOSYNC_ZYPPER_ROOT,
            os.path.join(repo.root, "etc/zypp/repos.d/"),
            REPOSYNC_ZYPPER_RPMDB_PATH,
            os.path.join(repo.root, "var/cache/zypp/raw/"),
            os.path.join(repo.root, "var/cache/zypp/solv/"),
        )
        # libzypp older Curl backend does not set Proxy-Authorization reliably.
        # The new Curl2 backend does not have the same problem.
        # See https://bugzilla.suse.com/show_bug.cgi?id=1245222 and
        # https://bugzilla.suse.com/show_bug.cgi?id=1245221
        zypper_env = os.environ.copy()
        zypper_env["ZYPP_CURL2"] = "1"
        # pylint: disable-next=subprocess-run-check
        process = subprocess.run(
            zypper_cmd.split(" "), stderr=subprocess.PIPE, env=zypper_env
        )

        if process.returncode:
            if process.stderr:
                raise RepoMDError(
                    # pylint: disable-next=consider-using-f-string
                    "Cannot access repository.\n{}".format(sstr(process.stderr))
                )
            raise RepoMDError(
                "Cannot access repository. Maybe repository GPG keys are not imported"
            )

        repo.is_configured = True

    def error_msg(self, message):
        rhnLog.log_clean(0, message)
        sys.stderr.write(str(message) + "\n")

    def _prep_zypp_repo_url(self, url, uln_repo):
        """
        Prepare the repository baseurl to use in the Zypper repo file.
        This will add the HTTP Proxy and Client certificate settings as part of
        the url parameters to be interpreted by CURL during the Zypper execution.

        :returns: str
        """
        # pylint: disable-next=unused-variable
        ret_url = None
        query_params = {}
        if self.proxy_hostname:
            query_params["proxy"] = quote(self.proxy_hostname)
        if self.proxy_user:
            query_params["proxyuser"] = quote(self.proxy_user)
        if self.proxy_pass:
            query_params["proxypass"] = quote(self.proxy_pass, safe="")
        if self.sslcacert:
            # Since Zypper only accepts CAPATH, we need to split the certificates bundle
            # and run "c_rehash" on our custom CAPATH
            # pylint: disable-next=invalid-name
            _ssl_capath = os.path.dirname(self.sslcacert)
            # pylint: disable-next=consider-using-f-string
            msg = "Preparing custom SSL CAPATH at {}".format(_ssl_capath)
            rhnLog.log_clean(0, msg)
            sys.stdout.write(str(msg) + "\n")
            os.system(
                # pylint: disable-next=consider-using-f-string
                '/usr/bin/awk \'BEGIN {{c=0;}} /BEGIN CERT/{{c++}} {{ print > "{0}/cert." c ".pem"}}\' < {1}'.format(
                    _ssl_capath, self.sslcacert
                )
            )
            # pylint: disable-next=consider-using-f-string
            os.system("/usr/bin/c_rehash {} 2&>1 /dev/null".format(_ssl_capath))
            query_params["ssl_capath"] = _ssl_capath
        if self.sslclientcert:
            query_params["ssl_clientcert"] = self.sslclientcert
        if self.sslclientkey:
            query_params["ssl_clientkey"] = self.sslclientkey
        # urlparse cannot handle uln urls, so we need to keep this check
        if uln_repo:
            new_query = unquote(urlencode(query_params, doseq=True))
            # pylint: disable-next=consider-using-f-string
            return "{0}&{1}".format(url, new_query)
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
        if parsed_url.username and parsed_url.password:
            creds_cfg = """
username={user}
password={passwd}
"""
            netloc = parsed_url.hostname
            if parsed_url.port:
                # pylint: disable-next=consider-using-f-string
                netloc = "{0}:{1}".format(netloc, parsed_url.port)
            cdir = os.path.join(REPOSYNC_ZYPPER_ROOT, "etc/zypp/credentials.d")
            if not os.path.exists(cdir):
                os.makedirs(cdir)
            cfile = os.path.join(cdir, str(self.channel_label or self.reponame))
            # pylint: disable-next=unspecified-encoding
            with open(cfile, "w") as creds_file:
                creds_file.write(
                    creds_cfg.format(
                        user=unquote(parsed_url.username),
                        passwd=unquote(parsed_url.password),
                    )
                )
                query_params["credentials"] = str(self.channel_label or self.reponame)
            os.chmod(cfile, int("0600", 8))
        new_query = unquote(urlencode(query_params, doseq=True))

        existing_query = parsed_url.query
        combined_query = "&".join([q for q in [existing_query, new_query] if q])
        return urlunparse(
            (
                parsed_url.scheme,
                netloc,
                parsed_url.path,
                parsed_url.params,
                combined_query,
                parsed_url.fragment,
            )
        )

    def _md_exists(self, tag):
        """
        Check if the requested metadata exists on the repository

        :returns: bool
        """
        if not self.repo.is_configured:
            self.setup_repo(self.repo)
        return bool(self._retrieve_md_path(tag))

    def _retrieve_md_path(self, tag):
        """
        Return the path to the requested metadata if exists

        :returns: str
        """
        if not self.repo.is_configured:
            self.setup_repo(self.repo)

        # pylint: disable-next=invalid-name
        _repodata_path = self._get_repodata_path()
        repomd_path = os.path.join(_repodata_path, "repomd.xml")
        if tag == "repomd":
            return repomd_path

        def get_location_from_xml_element(data_item):
            for sub_item in data_item:
                if sub_item.tag.endswith("location"):
                    return sub_item.attrib.get("href")

        path = None
        with open(repomd_path, "rb") as repomd:
            for _, elem in etree.iterparse(repomd):
                if elem.tag.endswith("data") and elem.attrib.get("type").startswith(
                    tag
                ):
                    path = os.path.join(
                        self.repo.root,
                        ZYPP_RAW_CACHE_PATH,
                        self.channel_label or self.reponame,
                        get_location_from_xml_element(elem),
                    )
                    if os.path.exists(path):
                        break
        if not path or not os.path.exists(path):
            return None
        return path

    def _get_repodata_path(self):
        """
        Return the path to the repository repodata directory

        :returns: str
        """
        if not self.repo.is_configured:
            self.setup_repo(self.repo)
        return os.path.join(
            self.repo.root,
            ZYPP_RAW_CACHE_PATH,
            self.channel_label or self.reponame,
            "repodata",
        )

    def get_md_checksum_type(self):
        """
        Return the checksum type of the primary.xml if exists, otherwise
        default output is "sha1".

        :returns: str
        """
        if self._md_exists("repomd"):
            repomd_path = self._retrieve_md_path("repomd")
            infile = fileutils.decompress_open(repomd_path)
            for repodata in etree.parse(infile).getroot():
                if repodata.get("type") == "primary":
                    checksum_elem = repodata.find(REPO_XML + "checksum")
                    return checksum_elem.get("type")
        return "sha1"

    def _get_solvable_packages(self):
        """
        Return the full list of solvable packages available at the configured repo.
        This information is read from the solv file created by Zypper.

        :returns: list
        """
        if not self.repo.is_configured:
            self.setup_repo(self.repo)
        self.solv_pool = solv.Pool()
        self.solv_repo = self.solv_pool.add_repo(
            str(self.channel_label or self.reponame)
        )
        solv_path = os.path.join(
            self.repo.root,
            ZYPP_SOLV_CACHE_PATH,
            self.channel_label or self.reponame,
            "solv",
        )
        if not os.path.isfile(solv_path) or not self.solv_repo.add_solv(
            solv.xfopen(str(solv_path)), 0
        ):
            raise SolvFileNotFound(solv_path)
        self.solv_pool.addfileprovides()
        self.solv_pool.createwhatprovides()
        # Solvables with ":" in name are not packages
        return [pack for pack in self.solv_repo.solvables if ":" not in pack.name]

    def _get_solvable_dependencies(self, solvables):
        """
        Return a list containing all passed solvables and all its calculated dependencies.

        For each solvable we explore the "SOLVABLE_REQUIRES" to add any new solvable where "SOLVABLE_PROVIDES"
        is matching the requirement. All the new solvables that are added will be again processed in order to get
        a new level of dependencies.

        The exploration of dependencies is done when all the solvables are been processed and no new solvables are added

        :returns: list
        """
        if not self.repo.is_configured:
            self.setup_repo(self.repo)
        known_solvables = set()

        new_deps = True
        next_solvables = solvables

        # Collect solvables dependencies in depth
        while new_deps:
            new_deps = False
            for sol in next_solvables:
                # Do not explore dependencies from solvables that are already proceesed
                if sol not in known_solvables:
                    # This solvable has not been proceesed yet. We need to calculate its dependencies
                    known_solvables.add(sol)
                    new_deps = True
                    # Adding solvables that provide the dependencies
                    # pylint: disable-next=invalid-name
                    for _req in sol.lookup_deparray(keyname=solv.SOLVABLE_REQUIRES):
                        next_solvables.extend(self.solv_pool.whatprovides(_req))
        return list(known_solvables)

    def _apply_filters(self, pkglist, filters):
        """
        Return a list of packages where defined filters were applied.

        :returns: list
        """
        if not filters:
            # if there's no include/exclude filter on command line or in database
            for p in self.repo.includepkgs:
                filters.append(("+", [p]))
            for p in self.repo.exclude:
                filters.append(("-", [p]))

        if filters:
            pkglist = self._filter_packages(
                pkglist, filters, nevra_filter=self.nevra_filter
            )
            pkglist = self._get_solvable_dependencies(pkglist)

            # Do not pull in dependencies if there're explicitly excluded
            pkglist = self._filter_packages(pkglist, filters, True, self.nevra_filter)
            self.num_excluded = self.num_packages - len(pkglist)

        return pkglist

    @staticmethod
    def _fix_encoding(text):
        if text is None:
            return None
        else:
            return str(text)

    @staticmethod
    def _filter_packages(packages, filters, exclude_only=False, nevra_filter=False):
        """implement include / exclude logic
        filters are: [ ('+', includelist1), ('-', excludelist1),
                       ('+', includelist2), ... ]
        """
        if filters is None:
            return

        selected = []
        excluded = []
        allmatched_include = []
        allmatched_exclude = []
        if exclude_only or filters[0][0] == "-":
            # first filter is exclude, start with full package list
            # and then exclude from it
            selected = packages
        else:
            excluded = packages

        for filter_item in filters:
            sense, pkg_list = filter_item
            regex = fnmatch.translate(pkg_list[0])
            reobj = re.compile(regex)
            if sense == "+":
                if exclude_only:
                    continue
                # include
                for excluded_pkg in excluded:
                    if nevra_filter:
                        pkg_name = str(excluded_pkg)
                    else:
                        pkg_name = excluded_pkg.name
                    if reobj.match(pkg_name):
                        allmatched_include.insert(0, excluded_pkg)
                        selected.insert(0, excluded_pkg)
                for pkg in allmatched_include:
                    if pkg in excluded:
                        excluded.remove(pkg)
            elif sense == "-":
                # exclude
                for selected_pkg in selected:
                    if nevra_filter:
                        pkg_name = str(selected_pkg)
                    else:
                        pkg_name = selected_pkg.name
                    if reobj.match(pkg_name):
                        allmatched_exclude.insert(0, selected_pkg)
                        excluded.insert(0, selected_pkg)
                for pkg in allmatched_exclude:
                    if pkg in selected:
                        selected.remove(pkg)
                excluded = excluded + allmatched_exclude
            else:
                raise IOError("Filters are malformed")
        return selected

    def get_susedata(self):
        """
        Return susedata metadata from the repository if available

        :returns: list
        """
        susedata = []
        if self._md_exists("susedata"):
            data_path = self._retrieve_md_path("susedata")
            infile = fileutils.decompress_open(data_path)
            for package in etree.parse(infile).getroot():
                d = {}
                d["pkgid"] = package.get("pkgid")
                d["name"] = package.get("name")
                d["arch"] = package.get("arch")
                d["keywords"] = []
                for child in package:
                    # we use "endswith" because sometimes it has a namespace
                    # and sometimes not :-(
                    if child.tag.endswith("version"):
                        d["version"] = child.get("ver")
                        d["release"] = child.get("rel")
                        d["epoch"] = child.get("epoch")
                        if d["epoch"] == "0" or d["epoch"] == "":
                            d["epoch"] = None
                        if child.get("arch"):
                            d["arch"] = child.get("arch")

                    elif child.tag.endswith("keyword"):
                        d["keywords"].append(child.text)
                    elif child.tag == "eula":
                        d["eula"] = child.text
                susedata.append(d)
        return susedata

    def get_products(self):
        """
        Return products metadata from the repository if available

        :returns: list
        """
        products = []
        if self._md_exists("products"):
            data_path = self._retrieve_md_path("products")
            infile = fileutils.decompress_open(data_path)
            for product in etree.parse(infile).getroot():
                p = {}
                p["name"] = product.find("name").text
                p["arch"] = product.find("arch").text
                version = product.find("version")
                p["version"] = version.get("ver")
                p["release"] = version.get("rel")
                p["epoch"] = version.get("epoch")
                p["vendor"] = self._fix_encoding(product.find("vendor").text)
                p["summary"] = self._fix_encoding(product.find("summary").text)
                p["description"] = self._fix_encoding(product.find("description").text)
                if p["epoch"] == "0":
                    p["epoch"] = None
                products.append(p)
        return products

    def get_updates(self):
        """
        Return update metadata from the repository if available

        :returns: list
        """
        if self._md_exists("updateinfo"):
            notices = {}
            updates_path = self._retrieve_md_path("updateinfo")
            infile = fileutils.decompress_open(updates_path)
            # pylint: disable-next=invalid-name,unused-variable
            for _event, elem in etree.iterparse(infile):
                if elem.tag == "update":
                    un = UpdateNotice(elem)
                    key = un["update_id"]
                    # pylint: disable-next=consider-using-f-string
                    key = "%s-%s" % (un["update_id"], un["version"])
                    if key not in notices:
                        notices[key] = un
            return ("updateinfo", notices.values())
        elif self._md_exists("patches"):
            patches_path = self._retrieve_md_path("patches")
            infile = fileutils.decompress_open(patches_path)
            notices = []
            for patch in etree.parse(infile).getroot():
                checksum_elem = patch.find(PATCHES_XML + "checksum")
                location_elem = patch.find(PATCHES_XML + "location")
                relative = location_elem.get("href")
                # pylint: disable-next=unused-variable
                checksum_type = checksum_elem.get("type")
                # pylint: disable-next=redefined-outer-name,unused-variable
                checksum = checksum_elem.text
                filename = os.path.join(
                    self._get_repodata_path(), os.path.basename(relative)
                )
                try:
                    notices.append(etree.parse(filename).getroot())
                except SyntaxError as e:
                    self.error_msg(
                        # pylint: disable-next=consider-using-f-string
                        "Could not parse %s. "
                        "The file is not a valid XML document. %s" % (filename, e.msg)
                    )
                    continue
            return ("patches", notices)
        else:
            return ("", [])

    def get_groups(self):
        """
        Return path to the repository groups metadata file if available

        :returns: str
        """
        # groups -> /var/cache/rhn/reposync/1/CentOS_7_os_x86_64/bc140c8149fc43a5248fccff0daeef38182e49f6fe75d9b46db1206dc25a6c1c-c7-x86_64-comps.xml.gz
        groups = None
        if self._md_exists("group"):
            groups = self._retrieve_md_path("group")
        return groups

    def get_modules(self):
        """
        Return path to the repository modules metadata file if available

        :returns: str
        """
        modules = None
        if self._md_exists("modules"):
            modules = self._retrieve_md_path("modules")
        return modules

    def get_mediaproducts(self):
        """
        Return path to media.1/products file if available

        :returns: str
        """
        url = "media.1/products"
        media_products_path = os.path.join(self._get_repodata_path(), url)
        grabber = urlgrabber.grabber.URLGrabber()
        mirror_group = MirrorGroup(grabber, self.repo.urls)
        try:
            urlgrabber_opts = {}
            self.set_download_parameters(urlgrabber_opts, url, media_products_path)
            mirror_group.urlgrab(url, media_products_path, **urlgrabber_opts)
        except URLGrabError as exc:
            repl_url = suseLibURL(url).getURL(stripPw=True)
            if not hasattr(exc, "code") and exc.errno != NO_MORE_MIRRORS_TO_TRY:
                # pylint: disable-next=consider-using-f-string
                msg = "ERROR: Media product file download failed: %s - %s" % (
                    url,
                    exc.strerror,
                )
                msg = msg.replace(url, repl_url)
                log(0, msg)
            if rhnLog.LOG and rhnLog.LOG.level >= 2:
                # pylint: disable-next=consider-using-f-string
                msg = "DEBUG[%s/%s]: Media product file download failed: %s - %s%s" % (
                    exc.errno,
                    exc.code if hasattr(exc, "code") else "-",
                    url,
                    exc.strerror,
                    # pylint: disable-next=consider-using-f-string
                    ": %s" % (traceback.format_exc()) if rhnLog.LOG.level >= 3 else "",
                )
                msg = msg.replace(url, repl_url)
                log(0, msg)
            # no 'media.1/products' file found
            return None
        return media_products_path

    def raw_list_packages(self, filters=None):
        """
        Return a raw list of available packages.

        :returns: list
        """
        rawpkglist = [
            RawSolvablePackage(solvable) for solvable in self._get_solvable_packages()
        ]
        return self._apply_filters(rawpkglist, filters)

    def list_packages(self, filters, latest):
        """
        List available packages.

        :returns: list
        """
        pkglist = self._get_solvable_packages()
        pkglist.sort(key=cmp_to_key(self._sort_packages))
        self.num_packages = len(pkglist)
        pkglist = self._apply_filters(pkglist, filters)

        if latest:
            latest_pkgs = {}
            # pylint: disable-next=unused-variable
            new_pkgs = []
            for pkg in pkglist:
                # pylint: disable-next=consider-using-f-string
                ident = "{}.{}".format(pkg.name, pkg.arch)
                # pylint: disable-next=consider-iterating-dictionary
                if ident not in latest_pkgs.keys() or looseversion.LooseVersion(
                    str(pkg.evr)
                ) > looseversion.LooseVersion(str(latest_pkgs[ident].evr)):
                    latest_pkgs[ident] = pkg
            pkglist = list(latest_pkgs.values())

        to_return = []
        for pack in pkglist:
            new_pack = ContentPackage()
            # pylint: disable-next=protected-access
            epoch, version, release = RawSolvablePackage._parse_solvable_evr(pack.evr)
            try:
                new_pack.setNVREA(pack.name, version, release, epoch, pack.arch)
            except ValueError as e:
                log(0, "WARNING: package contains incorrect metadata. SKIPPING!")
                log(0, e)
                continue
            new_pack.unique_id = RawSolvablePackage(pack)
            # pylint: disable-next=redefined-outer-name
            checksum = pack.lookup_checksum(solv.SOLVABLE_CHECKSUM)
            new_pack.checksum_type = checksum.typestr()
            new_pack.checksum = checksum.hex()
            to_return.append(new_pack)
        return to_return

    @staticmethod
    def _sort_packages(pkg1, pkg2):
        """sorts a list of deb package dicts by name"""
        if pkg1.name > pkg2.name:
            return 1
        elif pkg1.name == pkg2.name:
            return 0
        else:
            return -1

    def clear_cache(self, directory=None, keep_repomd=False):
        """
        Clear all cache files from the environment.

        """
        if directory is None:
            directory = self.repo.root

        # remove content in directory
        for item in os.listdir(directory):
            path = os.path.join(directory, item)
            if os.path.isfile(path) and not (keep_repomd and item == "repomd.xml"):
                os.unlink(path)
            elif os.path.isdir(path):
                rmtree(path)

    def get_metadata_paths(self):
        """
        Simply return the 'primary' and 'updateinfo' path from repomd

        Example output:
        [
            (
                'repodata/bc140c8149fc43a5248fccff0daeef38182e49f6fe75d9b46db1206dc25a6c1c-c7-x86_64-comps.xml.gz',
                ('sha256', 'bc140c8149fc43a5248fccff0daeef38182e49f6fe75d9b46db1206dc25a6c1c')
            ),
            (
                'repodata/6614b3605d961a4aaec45d74ac4e5e713e517debb3ee454a1c91097955780697-primary.sqlite.bz2',
                ('sha256', '6614b3605d961a4aaec45d74ac4e5e713e517debb3ee454a1c91097955780697')
            )
        ]

        :returns: list
        """

        def get_location(data_item):
            for sub_item in data_item:
                if sub_item.tag.endswith("location"):
                    return sub_item.attrib.get("href")

        def get_checksum(data_item):
            for sub_item in data_item:
                if sub_item.tag.endswith("checksum"):
                    return sub_item.attrib.get("type"), sub_item.text

        if self._md_exists("repomd"):
            repomd_path = self._retrieve_md_path("repomd")
        else:
            raise RepoMDError(self._get_repodata_path())
        repomd = open(repomd_path, "rb")
        files = {}
        # pylint: disable-next=invalid-name,unused-variable
        for _event, elem in etree.iterparse(repomd):
            if elem.tag.endswith("data"):
                if elem.attrib.get("type") == "primary_db":
                    files["primary"] = (get_location(elem), get_checksum(elem))
                elif elem.attrib.get("type") == "primary" and "primary" not in files:
                    files["primary"] = (get_location(elem), get_checksum(elem))
                elif elem.attrib.get("type") == "updateinfo":
                    files["updateinfo"] = (get_location(elem), get_checksum(elem))
                elif elem.attrib.get("type") == "group_gz":
                    files["group"] = (get_location(elem), get_checksum(elem))
                elif elem.attrib.get("type") == "group" and "group" not in files:
                    files["group"] = (get_location(elem), get_checksum(elem))
                elif elem.attrib.get("type") == "modules":
                    files["modules"] = (get_location(elem), get_checksum(elem))
        repomd.close()
        return list(files.values())

    def repomd_up_to_date(self):
        """
        Check if repomd.xml has been updated by spacewalk.

        :returns: bool
        """
        if self._md_exists("repomd"):
            repomd_old_path = self._retrieve_md_path("repomd")
            repomd_new_path = os.path.join(self._get_repodata_path(), "repomd.xml.new")
            # Newer file not available? Don't do anything. It should be downloaded before this.
            if not os.path.isfile(repomd_new_path):
                return True
            return checksum.getFileChecksum(
                "sha256", filename=repomd_old_path
            ) == checksum.getFileChecksum("sha256", filename=repomd_new_path)
        else:
            return False

    # Get download parameters for threaded downloader
    def set_download_parameters(
        self,
        params,
        relative_path,
        target_file=None,
        checksum_type=None,
        checksum_value=None,
        bytes_range=None,
    ):
        # Create directories if needed
        if target_file is not None:
            target_dir = os.path.dirname(target_file)
            if not os.path.exists(target_dir):
                os.makedirs(target_dir, int("0755", 8))

        params["urls"] = self.repo.urls
        params["relative_path"] = relative_path
        params["authtoken"] = self.authtoken
        params["target_file"] = target_file
        params["ssl_ca_cert"] = self.sslcacert
        params["ssl_client_cert"] = self.sslclientcert
        params["ssl_client_key"] = self.sslclientkey
        params["checksum_type"] = checksum_type
        params["checksum"] = checksum_value
        params["bytes_range"] = bytes_range
        params["http_headers"] = tuple(self.http_headers.items())
        params["timeout"] = self.timeout
        params["minrate"] = self.minrate
        params["proxies"] = get_proxies(
            self.proxy_url, self.proxy_user, self.proxy_pass
        )
        # pylint: disable-next=redefined-outer-name,invalid-name
        with cfg_component("server.satellite") as CFG:
            params["urlgrabber_logspec"] = CFG.get("urlgrabber_logspec")

    def get_file(self, path, local_base=None):
        try:
            try:
                grabber = urlgrabber.grabber.URLGrabber()
                mirror_group = MirrorGroup(grabber, self.repo.urls)
                temp_file = ""

                if local_base is not None:
                    target_file = os.path.join(local_base, path)
                    target_dir = os.path.dirname(target_file)
                    if not os.path.exists(target_dir):
                        os.makedirs(target_dir, int("0755", 8))
                    temp_file = target_file + "..download"
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)
                    urlgrabber_opts = {}
                    self.set_download_parameters(urlgrabber_opts, path, temp_file)
                    downloaded = mirror_group.urlgrab(
                        path, temp_file, **urlgrabber_opts
                    )
                    os.rename(downloaded, target_file)
                    return target_file
                else:
                    urlgrabber_opts = {}
                    self.set_download_parameters(urlgrabber_opts, path)
                    return mirror_group.urlread(path, **urlgrabber_opts)
            except urlgrabber.grabber.URLGrabError:
                return
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def set_ssl_options(self, ca_cert, client_cert, client_key):
        self.sslcacert = ca_cert
        self.sslclientcert = client_cert
        self.sslclientkey = client_key

    def _authenticate(self, url):
        pass
