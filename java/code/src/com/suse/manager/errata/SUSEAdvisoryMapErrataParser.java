/*
 * Copyright (c) 2025 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 */
package com.suse.manager.errata;

import com.redhat.rhn.domain.errata.Errata;

import com.suse.manager.errata.advisorymap.ErrataAdvisoryMapFactory;

import java.net.URI;
import java.net.URISyntaxException;

public class SUSEAdvisoryMapErrataParser implements VendorSpecificErrataParser {

    /**
     * {@inheritDoc}
     */
    @Override
    public URI getAdvisoryUri(Errata errata) throws ErrataParsingException {
        return getAdvisoryUri(errata.getAdvisory());
    }

    /**
     * Retrieve the URI of SUSE vendor advisory represented by the given errata advisory.
     *
     * @param errataAdvisory the errata advisory.
     * @return a URI representing the http address of the advisory.
     * @throws ErrataParsingException if the required pieces of information are missing in the errata object.
     */
    public URI getAdvisoryUri(String errataAdvisory) throws ErrataParsingException {
        ErrataAdvisoryMapFactory advisoryMapFactory = new ErrataAdvisoryMapFactory();

        try {
            String uri = advisoryMapFactory
                    .lookupByAdvisory(errataAdvisory)
                    .map(item -> item.getAdvisoryUri())
                    .orElseThrow(() -> new ErrataParsingException(
                            "Unable generate vendor link for errata: " + errataAdvisory));
            return new URI(uri);
        }
        catch (URISyntaxException ex) {
            throw new ErrataParsingException("Unable generate vendor link for errata", ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getAnnouncementId(Errata errata) throws ErrataParsingException {
        return getAnnouncementId(errata.getAdvisory());
    }


    /**
     * Retrieve the SUSE vendor announcement id
     *
     * @param errataAdvisory the errata advisory.
     * @return a string defining the id of SUSE advisory announcement.
     * @throws ErrataParsingException if the required pieces of information are missing in the errata object.
     */
    public String getAnnouncementId(String errataAdvisory) throws ErrataParsingException {
        ErrataAdvisoryMapFactory advisoryMapFactory = new ErrataAdvisoryMapFactory();

        return advisoryMapFactory
                .lookupByAdvisory(errataAdvisory)
                .map(item -> item.getAnnouncementId())
                .orElseThrow(() -> new ErrataParsingException(
                        "Unable generate announcement id for errata: " + errataAdvisory));
    }
}
