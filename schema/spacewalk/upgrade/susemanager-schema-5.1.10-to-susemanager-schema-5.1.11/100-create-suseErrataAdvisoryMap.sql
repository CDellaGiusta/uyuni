--
-- Copyright (c) 2025 SUSE LLC
--
-- This software is licensed to you under the GNU General Public License,
-- version 2 (GPLv2). There is NO WARRANTY for this software, express or
-- implied, including the implied warranties of MERCHANTABILITY or FITNESS
-- FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
-- along with this software; if not, see
-- http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
--
--

CREATE TABLE IF NOT EXISTS suseErrataAdvisoryMap
(
    id            BIGINT CONSTRAINT suse_errata_advisory_map_id_pk PRIMARY KEY
                                                  GENERATED ALWAYS AS IDENTITY,
    patch_id     VARCHAR(128),
    announcement_id           VARCHAR(64),
    advisory_uri   TEXT,

    created        TIMESTAMPTZ
                       DEFAULT (current_timestamp) NOT NULL,
    modified       TIMESTAMPTZ
                       DEFAULT (current_timestamp) NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS suse_errata_advisory_map_patch_id_idx
    ON suseErrataAdvisoryMap (patch_id);

