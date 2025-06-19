/*
 * Copyright (c) 2025 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 */
package com.suse.manager.errata.advisorymap;

import com.redhat.rhn.domain.BaseDomainHelper;

import java.util.Objects;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "suseErrataAdvisoryMap")
public class ErrataAdvisoryMap extends BaseDomainHelper {

    private Long id;
    private String advisory;
    private String announcementId;
    private String advisoryUri;

    /**
     * Default constructor
     */
    public ErrataAdvisoryMap() {
        this(null, null, null);
    }

    /**
     * Constructor
     *
     * @param advisoryIn
     * @param announcementIdIn
     * @param advisoryUriIn
     */
    public ErrataAdvisoryMap(String advisoryIn, String announcementIdIn, String advisoryUriIn) {
        advisory = advisoryIn;
        announcementId = announcementIdIn;
        advisoryUri = advisoryUriIn;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    public void setId(Long idIn) {
        id = idIn;
    }

    public String getAdvisory() {
        return advisory;
    }

    public void setAdvisory(String advisoryIn) {
        advisory = advisoryIn;
    }

    @Column(name = "announcement_id")
    public String getAnnouncementId() {
        return announcementId;
    }

    public void setAnnouncementId(String announcementIdIn) {
        announcementId = announcementIdIn;
    }

    @Column(name = "advisory_uri")
    public String getAdvisoryUri() {
        return advisoryUri;
    }

    public void setAdvisoryUri(String advisoryUriIn) {
        advisoryUri = advisoryUriIn;
    }

    @Override
    public boolean equals(Object oIn) {
        if (!(oIn instanceof ErrataAdvisoryMap that)) {
            return false;
        }
        return Objects.equals(getId(), that.getId()) &&
                Objects.equals(getAdvisory(), that.getAdvisory()) &&
                Objects.equals(getAnnouncementId(), that.getAnnouncementId()) &&
                Objects.equals(getAdvisoryUri(), that.getAdvisoryUri());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId(),
                getAdvisory(),
                getAnnouncementId(),
                getAdvisoryUri());
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("ErrataAdvisoryMap{");
        sb.append("id=").append(id);
        sb.append(", advisory='").append(advisory).append('\'');
        sb.append(", announcementId='").append(announcementId).append('\'');
        sb.append(", advisoryUri='").append(advisoryUri).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
