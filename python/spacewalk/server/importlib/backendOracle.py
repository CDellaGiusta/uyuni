#  pylint: disable=missing-module-docstring,invalid-name
#
# Copyright (c) 2008--2017 Red Hat, Inc.
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
#
# Oracle-specific stuff
#
# FIXME: need more documentation
#

# pylint: disable-next=unused-import
import sys
from .backend import Backend
from .backendLib import (
    DBint,
    DBstring,
    DBdateTime,
    Table,
    TableCollection,
    DBblob,
    DBbool,
)
from spacewalk.server import rhnSQL
from spacewalk.server.rhnSQL.const import POSTGRESQL
from spacewalk.common.rhnConfig import CFG
from uyuni.common import timezone_utils


# pylint: disable-next=missing-class-docstring
class OracleBackend(Backend):
    tables = TableCollection(
        # NOTE: pk = primary keys
        #       attribute = attribute this table links back to
        #       map = mapping from database fields to generic attribute names
        Table(
            "rhnPackageProvides",
            fields={
                "package_id": DBint(),
                "capability_id": DBint(),
                "sense": DBint(),
            },
            pk=["package_id", "capability_id", "sense"],
            attribute="provides",
            map={
                "sense": "flags",
            },
        ),
        Table(
            "rhnPackageRequires",
            fields={
                "package_id": DBint(),
                "capability_id": DBint(),
                "sense": DBint(),
            },
            pk=["package_id", "capability_id", "sense"],
            attribute="requires",
            map={
                "sense": "flags",
            },
        ),
        Table(
            "rhnPackageConflicts",
            fields={
                "package_id": DBint(),
                "capability_id": DBint(),
                "sense": DBint(),
            },
            pk=["package_id", "capability_id", "sense"],
            attribute="conflicts",
            map={
                "sense": "flags",
            },
        ),
        Table(
            "rhnPackageObsoletes",
            fields={
                "package_id": DBint(),
                "capability_id": DBint(),
                "sense": DBint(),
            },
            pk=["package_id", "capability_id", "sense"],
            attribute="obsoletes",
            map={
                "sense": "flags",
            },
        ),
        Table(
            "rhnPackageRecommends",
            fields={
                "package_id": DBint(),
                "capability_id": DBint(),
                "sense": DBint(),
            },
            pk=["package_id", "capability_id", "sense"],
            attribute="recommends",
            map={
                "sense": "flags",
            },
        ),
        Table(
            "rhnPackageSuggests",
            fields={
                "package_id": DBint(),
                "capability_id": DBint(),
                "sense": DBint(),
            },
            pk=["package_id", "capability_id", "sense"],
            attribute="suggests",
            map={
                "sense": "flags",
            },
        ),
        Table(
            "rhnPackageSupplements",
            fields={
                "package_id": DBint(),
                "capability_id": DBint(),
                "sense": DBint(),
            },
            pk=["package_id", "capability_id", "sense"],
            attribute="supplements",
            map={
                "sense": "flags",
            },
        ),
        Table(
            "rhnPackageEnhances",
            fields={
                "package_id": DBint(),
                "capability_id": DBint(),
                "sense": DBint(),
            },
            pk=["package_id", "capability_id", "sense"],
            attribute="enhances",
            map={
                "sense": "flags",
            },
        ),
        Table(
            "rhnPackageBreaks",
            fields={
                "package_id": DBint(),
                "capability_id": DBint(),
                "sense": DBint(),
            },
            pk=["package_id", "capability_id", "sense"],
            attribute="breaks",
            map={
                "sense": "flags",
            },
        ),
        Table(
            "rhnPackagePredepends",
            fields={
                "package_id": DBint(),
                "capability_id": DBint(),
                "sense": DBint(),
            },
            pk=["package_id", "capability_id", "sense"],
            attribute="predepends",
            map={
                "sense": "flags",
            },
        ),
        Table(
            "rhnPackageChangeLogRec",
            fields={
                "id": DBint(),
                "package_id": DBint(),
                "changelog_data_id": DBint(),
            },
            pk=["package_id", "changelog_data_id"],
            attribute="changelog",
            sequenceColumn="id",
        ),
        Table(
            "rhnPackageChangeLogData",
            fields={
                "id": DBint(),
                "name": DBstring(128),
                "text": DBblob(),
                "time": DBdateTime(),
            },
        ),
        Table(
            "rhnPackageFile",
            fields={
                "package_id": DBint(),
                "capability_id": DBint(),
                "device": DBint(),
                "inode": DBint(),
                "file_mode": DBint(),
                "username": DBstring(32),
                "groupname": DBstring(32),
                "rdev": DBint(),
                "file_size": DBint(),
                "mtime": DBdateTime(),
                "checksum_id": DBint(),
                "linkto": DBstring(256),
                "flags": DBint(),
                "verifyflags": DBint(),
                "lang": DBstring(32),
            },
            pk=["package_id", "capability_id"],
            attribute="files",
            severityHash={
                "mtime": 0,
                "file_size": 4,
            },
        ),
        Table(
            "rhnPackage",
            fields={
                "id": DBint(),
                "org_id": DBint(),
                "name_id": DBint(),
                "evr_id": DBint(),
                "package_arch_id": DBint(),
                "package_group": DBint(),
                "rpm_version": DBstring(16),
                "description": DBstring(4000),
                "summary": DBstring(4000),
                "package_size": DBint(),
                "payload_size": DBint(),
                "installed_size": DBint(),
                "build_host": DBstring(256),
                "build_time": DBdateTime(),
                "source_rpm_id": DBint(),
                "checksum_id": DBint(),
                "vendor": DBstring(64),
                "payload_format": DBstring(32),
                "path": DBstring(1000),
                "copyright": DBstring(128),
                "is_ptf": DBbool(),
                "is_part_of_ptf": DBbool(),
                "cookie": DBstring(128),
                "header_start": DBint(),
                "header_end": DBint(),
                "last_modified": DBdateTime(),
            },
            pk=["org_id", "name_id", "evr_id", "package_arch_id", "checksum_id"],
            nullable=["org_id"],
            severityHash={
                "path": 1,
                "package_size": 2,
                "build_time": 3,
                "build_host": 3,
                "last_modified": 0.5,
                # rpm got it wrong so now we have to ignore it
                "payload_size": 0,
            },
        ),
        Table(
            "rhnChannelPackage",
            fields={
                "package_id": DBint(),
                "channel_id": DBint(),
            },
            pk=["channel_id", "package_id"],
        ),
        Table(
            "rhnErrata",
            fields={
                "id": DBint(),
                "advisory": DBstring(100),
                "advisory_type": DBstring(32),
                "advisory_status": DBstring(32),
                "advisory_name": DBstring(100),
                "advisory_rel": DBint(),
                "product": DBstring(64),
                "description": DBstring(4000),
                "synopsis": DBstring(4000),
                "topic": DBstring(4000),
                "solution": DBstring(4000),
                "rights": DBstring(100),
                "notes": DBstring(4000),
                "refers_to": DBstring(4000),
                "org_id": DBint(),
                "locally_modified": DBstring(1),
                "severity_id": DBint(),
                "errata_from": DBstring(127),
                # We will treat issue_date and update_date as regular dates
                # with times instead of DBdate types, otherwise we'd have
                # issues with timezones
                "issue_date": DBdateTime(),
                "update_date": DBdateTime(),
                "last_modified": DBdateTime(),
            },
            pk=["advisory_name", "org_id"],
            nullable=["org_id"],
            defaultSeverity=4,
        ),
        Table(
            "rhnErrataBugList",
            fields={
                "errata_id": DBint(),
                "bug_id": DBint(),
                "summary": DBstring(4000),
                "href": DBstring(255),
            },
            pk=["errata_id", "bug_id"],
            attribute="bugs",
            defaultSeverity=4,
        ),
        Table(
            "rhnCVE",
            fields={
                "id": DBint(),
                "name": DBstring(20),
            },
            pk=["name"],
        ),
        Table(
            "rhnErrataCVE",
            fields={
                "errata_id": DBint(),
                "cve_id": DBint(),
            },
            pk=["errata_id", "cve_id"],
            attribute="cve",
            defaultSeverity=4,
        ),
        Table(
            "rhnErrataFile",
            fields={
                "id": DBint(),
                "errata_id": DBint(),
                "type": DBint(),
                "checksum_id": DBint(),
                "filename": DBstring(4000),
            },
            pk=["errata_id", "filename", "checksum_id"],
            attribute="files",
            defaultSeverity=4,
            sequenceColumn="id",
        ),
        Table(
            "rhnErrataFilePackage",
            fields={
                "errata_file_id": DBint(),
                "package_id": DBint(),
            },
            pk=["errata_file_id", "package_id"],
        ),
        Table(
            "rhnErrataFilePackageSource",
            fields={
                "errata_file_id": DBint(),
                "package_id": DBint(),
            },
            pk=["errata_file_id", "package_id"],
        ),
        Table(
            "rhnErrataFileChannel",
            fields={
                "errata_file_id": DBint(),
                "channel_id": DBint(),
            },
            pk=["errata_file_id", "channel_id"],
        ),
        Table(
            "rhnErrataKeyword",
            fields={
                "errata_id": DBint(),
                "keyword": DBstring(64),
            },
            pk=["errata_id", "keyword"],
            attribute="keywords",
            defaultSeverity=4,
        ),
        Table(
            "rhnErrataPackage",
            fields={
                "errata_id": DBint(),
                "package_id": DBint(),
            },
            pk=["errata_id", "package_id"],
            attribute="packages",
            defaultSeverity=4,
        ),
        Table(
            "rhnChannelErrata",
            fields={
                "errata_id": DBint(),
                "channel_id": DBint(),
            },
            pk=["errata_id", "channel_id"],
            attribute="channels",
            defaultSeverity=4,
        ),
        Table(
            "rhnChannel",
            fields={
                "id": DBint(),
                "parent_channel": DBint(),
                "org_id": DBint(),
                "channel_arch_id": DBint(),
                "label": DBstring(128),
                "basedir": DBstring(256),
                "name": DBstring(256),
                "summary": DBstring(500),
                "description": DBstring(4000),
                "product_name_id": DBint(),
                "gpg_key_url": DBstring(256),
                "gpg_key_id": DBstring(14),
                "gpg_key_fp": DBstring(50),
                "end_of_life": DBdateTime(),
                "receiving_updates": DBstring(1),
                "last_modified": DBdateTime(),
                "channel_product_id": DBint(),
                "checksum_type_id": DBint(),
                "channel_access": DBstring(10),
                "update_tag": DBstring(128),
                "installer_updates": DBstring(1),
            },
            pk=["label"],
            severityHash={
                "channel_product_id": 0,
            },
        ),
        Table(
            "rhnChannelFamily",
            fields={
                "id": DBint(),
                "name": DBstring(128),
                "label": DBstring(128),
            },
            pk=["label"],
            defaultSeverity=4,
        ),
        Table(
            "rhnDistChannelMap",
            fields={
                "os": DBstring(64),
                "release": DBstring(64),
                "channel_arch_id": DBint(),
                "channel_id": DBint(),
                "org_id": DBint(),
            },
            pk=["release", "channel_arch_id", "org_id"],
            attribute="dists",
            defaultSeverity=4,
        ),
        Table(
            "rhnReleaseChannelMap",
            fields={
                "product": DBstring(64),
                "version": DBstring(64),
                "release": DBstring(64),
                "channel_arch_id": DBint(),
                "channel_id": DBint(),
            },
            pk=["product", "version", "release", "channel_arch_id", "channel_id"],
            attribute="release",
            defaultSeverity=4,
        ),
        Table(
            "rhnChannelTrust",
            fields={
                "channel_id": DBint(),
                "org_trust_id": DBint(),
            },
            pk=["channel_id", "org_trust_id"],
            attribute="trust_list",
            defaultSeverity=4,
        ),
        Table(
            "rhnChannelFamilyMembers",
            fields={
                "channel_id": DBint(),
                "channel_family_id": DBint(),
            },
            pk=["channel_id", "channel_family_id"],
            attribute="families",
            defaultSeverity=4,
        ),
        Table(
            "rhnPackageSource",
            fields={
                "id": DBint(),
                "org_id": DBint(),
                "source_rpm_id": DBint(),
                "package_group": DBint(),
                "rpm_version": DBstring(16),
                "payload_size": DBint(),
                "build_host": DBstring(256),
                "build_time": DBdateTime(),
                "path": DBstring(1000),
                "package_size": DBint(),
                "checksum_id": DBint(),
                "sigchecksum_id": DBint(),
                "vendor": DBstring(64),
                "cookie": DBstring(128),
                "last_modified": DBdateTime(),
            },
            pk=["source_rpm_id", "org_id", "sigchecksum_id", "checksum_id"],
            nullable=["org_id"],
            severityHash={
                "path": 1,
                "file_size": 2,
                "build_host": 3,
                "build_time": 3,
                # rpm got it wrong so now we have to ignore it
                "payload_size": 0,
                "last_modified": 0.5,
            },
        ),
        Table(
            "rhnServerArch",
            fields={
                "id": DBint(),
                "label": DBstring(64),
                "name": DBstring(64),
                "arch_type_id": DBint(),
            },
            pk=["label"],
        ),
        Table(
            "rhnPackageArch",
            fields={
                "id": DBint(),
                "label": DBstring(64),
                "name": DBstring(64),
                "arch_type_id": DBint(),
            },
            pk=["label"],
        ),
        Table(
            "rhnChannelArch",
            fields={
                "id": DBint(),
                "label": DBstring(64),
                "name": DBstring(64),
                "arch_type_id": DBint(),
            },
            pk=["label"],
        ),
        Table(
            "rhnCPUArch",
            fields={
                "id": DBint(),
                "label": DBstring(64),
                "name": DBstring(64),
            },
            pk=["label"],
        ),
        Table(
            "rhnServerPackageArchCompat",
            fields={
                "server_arch_id": DBint(),
                "package_arch_id": DBint(),
                "preference": DBint(),
            },
            pk=["server_arch_id", "package_arch_id", "preference"],
        ),
        Table(
            "rhnServerChannelArchCompat",
            fields={
                "server_arch_id": DBint(),
                "channel_arch_id": DBint(),
            },
            pk=["server_arch_id", "channel_arch_id"],
        ),
        Table(
            "rhnChannelPackageArchCompat",
            fields={
                "channel_arch_id": DBint(),
                "package_arch_id": DBint(),
            },
            pk=["channel_arch_id", "package_arch_id"],
        ),
        Table(
            "rhnServerServerGroupArchCompat",
            fields={
                "server_arch_id": DBint(),
                "server_group_type": DBint(),
            },
            pk=["server_arch_id", "server_group_type"],
        ),
        Table(
            "rhnKickstartableTree",
            fields={
                "id": DBint(),
                "org_id": DBint(),
                "base_path": DBstring(256),
                "channel_id": DBint(),
                "label": DBstring(64),
                "boot_image": DBstring(128),
                "kstree_type": DBint(),
                "install_type": DBint(),
                "last_modified": DBdateTime(),
            },
            pk=["label", "org_id"],
            nullable=["org_id"],
        ),
        Table(
            "rhnKSTreeType",
            # not used at the moment
            fields={
                "id": DBint(),
                "label": DBstring(32),
                "name": DBstring(64),
            },
            pk=["label"],
        ),
        Table(
            "rhnKSInstallType",
            # not used at the moment
            fields={
                "id": DBint(),
                "label": DBstring(32),
                "name": DBstring(64),
            },
            pk=["label"],
        ),
        Table(
            "rhnKSTreeFile",
            fields={
                "kstree_id": DBint(),
                "relative_filename": DBstring(256),
                "checksum_id": DBint(),
                "file_size": DBint(),
                "last_modified": DBdateTime(),
            },
            pk=["kstree_id", "relative_filename", "checksum_id"],
            attribute="files",
            map={
                "relative_filename": "relative_path",
            },
        ),
        Table(
            "rhnProductName",
            fields={
                "id": DBint(),
                "label": DBstring(128),
                "name": DBstring(128),
            },
            pk=["id", "label", "name"],
        ),
        Table(
            "rhnContentSource",
            fields={
                "id": DBint(),
                "org_id": DBint(),
                "label": DBstring(128),
                "source_url": DBstring(2048),
                "type_id": DBint(),
            },
            pk=["label", "org_id", "type_id"],
            nullable=["org_id"],
        ),
        Table(
            "rhnContentSourceSsl",
            fields={
                "content_source_id": DBint(),
                "ssl_ca_cert_id": DBint(),
                "ssl_client_cert_id": DBint(),
                "ssl_client_key_id": DBint(),
            },
            attribute="ssl-sets",
            pk=[
                "content_source_id",
                "ssl_ca_cert_id",
                "ssl_client_cert_id",
                "ssl_client_key_id",
            ],
            nullable=["ssl_client_cert_id", "ssl_client_key_id"],
        ),
        Table(
            "suseProductFile",
            fields={
                "id": DBint(),
                "name": DBstring(256),
                "evr_id": DBint(),
                "package_arch_id": DBint(),
                "vendor": DBstring(256),
                "summary": DBstring(4000),
                "description": DBstring(4000),
            },
            pk=["id"],
            nullable=["vendor", "summary", "description"],
        ),
        Table(
            "susePackageProductFile",
            fields={
                "package_id": DBint(),
                "prodfile_id": DBint(),
            },
            pk=["package_id", "prodfile_id"],
            attribute="product_files",
        ),
        Table(
            "suseEula",
            fields={
                "id": DBint(),
                "text": DBblob(),
                "checksum": DBstring(64),
            },
            pk=["id"],
            nullable=[],
        ),
        Table(
            "susePackageEula",
            fields={
                "package_id": DBint(),
                "eula_id": DBint(),
            },
            pk=["package_id", "eula_id"],
            attribute="eulas",
        ),
        Table(
            "rhnPackageExtraTag",
            fields={
                "package_id": DBint(),
                "key_id": DBint(),
                "value": DBstring(2048),
            },
            pk=["package_id", "key_id"],
            attribute="extra_tags",
        ),
    )

    def __init__(self):
        Backend.__init__(self, rhnSQL)

    def setSessionTimeZoneToLocalTimeZone(self):
        sth = self.dbmodule.prepare(
            # pylint: disable-next=consider-using-f-string
            "alter session set time_zone = '%s'"
            % timezone_utils.get_utc_offset()
        )
        sth.execute()

    def setSessionTimeZoneToUTC(self):
        sth = self.dbmodule.prepare("alter session set time_zone = 'UTC'")
        sth.execute()

    def init(self):
        """
        Override parent to do explicit setting of the date format. (Oracle
        specific)
        """
        # Set date format
        self.setSessionTimeZoneToLocalTimeZone()
        self.setDateFormat("YYYY-MM-DD HH24:MI:SS")
        return Backend.init(self)


class PostgresqlBackend(OracleBackend):
    """
    PostgresqlBackend specific implementation. The bulk of the OracleBackend
    is not actually Oracle specific, so we'll re-use as much as we can and just
    avoid the few bits that are.
    """

    def setSessionTimeZoneToLocalTimeZone(self):
        sth = self.dbmodule.prepare(
            # pylint: disable-next=consider-using-f-string
            "set session time zone '%s'"
            % timezone_utils.get_utc_offset()
        )
        sth.execute()

    def setSessionTimeZoneToUTC(self):
        sth = self.dbmodule.prepare("set session time zone 'UTC'")
        sth.execute()

    def init(self):
        """
        Avoid the Oracle specific stuff here in parent method.
        """
        self.setSessionTimeZoneToLocalTimeZone()
        return Backend.init(self)


def SQLBackend():
    if CFG.DB_BACKEND == POSTGRESQL:
        backend = PostgresqlBackend()
        backend.init()
        return backend
    else:
        raise ValueError("The selected DB_BACKEND is not supported")
