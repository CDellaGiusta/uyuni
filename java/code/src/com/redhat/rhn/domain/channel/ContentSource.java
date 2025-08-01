/*
 * Copyright (c) 2009--2017 Red Hat, Inc.
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
/*
 * Copyright (c) 2010 SUSE LLC
 */
package com.redhat.rhn.domain.channel;

import com.redhat.rhn.domain.BaseDomainHelper;
import com.redhat.rhn.domain.Identifiable;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.scc.SCCRepositoryAuth;

import java.util.HashSet;
import java.util.Set;

/**
 * ContentSourceType
 */
public class ContentSource extends BaseDomainHelper implements Identifiable {

    private Long id;
    private Org org;
    private ContentSourceType type;
    private String sourceUrl;
    private String label;
    private boolean metadataSigned;
    private Set<Channel> channels = new HashSet<>();
    private Set<SslContentSource> sslSets = new HashSet<>();
    private SCCRepositoryAuth repositoryAuth;

    /**
     * Constructor
     */
    public ContentSource() {
    }

    /**
     * Copy Constructor
     * @param cs content source template
     */
    public ContentSource(ContentSource cs) {
        org = cs.getOrg();
        type = cs.getType();
        sourceUrl = cs.getSourceUrl();
        label = cs.getLabel();
        metadataSigned = cs.getMetadataSigned();
        channels = new HashSet<>(cs.getChannels());
        sslSets = new HashSet<>(cs.getSslSets());
        repositoryAuth = cs.getRepositoryAuth();
    }


    /**
     * @return Returns the label.
     */
    public String getLabel() {
        return label;
    }


    /**
     * @param labelIn The label to set.
     */
    public void setLabel(String labelIn) {
        this.label = labelIn;
    }

    /**
     *
     * @return Org this content source belongs to
     */
    public Org getOrg() {
        return org;
    }

    /**
     *
     * @param orgIn Org to set
     */
    public void setOrg(Org orgIn) {
        org = orgIn;
    }

    /**
     * @return Returns the id.
     */
    @Override
    public Long getId() {
        return id;
    }

    /**
     * @param idIn The id to set.
     */
    public void setId(Long idIn) {
        this.id = idIn;
    }

    /**
     * @return Returns metadataSigned
     */
    public boolean getMetadataSigned() {
        return this.metadataSigned;
    }

    /**
     * @param md set metadataSigned
     */
    public void setMetadataSigned(boolean md) {
        this.metadataSigned = md;
    }

    /**
     * @return Returns the type.
     */
    public ContentSourceType getType() {
        return type;
    }


    /**
     * @param typeIn The type to set.
     */
    public void setType(ContentSourceType typeIn) {
        this.type = typeIn;
    }


    /**
     * @return Returns the sourceUrl.
     */
    public String getSourceUrl() {
        return sourceUrl;
    }


    /**
     * @param sourceUrlIn The sourceUrl to set.
     */
    public void setSourceUrl(String sourceUrlIn) {
        this.sourceUrl = sourceUrlIn;
    }

    /**
     *
     * @param channelsIn of channels this repo is pushed to
     */
    public void setChannels(Set<Channel> channelsIn) {
        this.channels = channelsIn;
    }

    /**
     *
     * @return set of channels that this repo will be pushed to
     */
    public Set<Channel> getChannels() {
        return channels;
    }

    /**
     *
     * @return SSL sets for content source
     */
    public Set<SslContentSource> getSslSets() {
        return sslSets;
    }

    /**
     *
     * @param sslSetsIn SSL sets to assign to repository
     */
    public void setSslSets(Set<SslContentSource> sslSetsIn) {
        this.sslSets = sslSetsIn;
    }

    /**
     * @return repositoryAuth object or null
     */
    public SCCRepositoryAuth getRepositoryAuth() {
        return repositoryAuth;
    }

    /**
     * @param repoAuth repository auth object to set
     */
    public void setRepositoryAuth(SCCRepositoryAuth repoAuth) {
        repositoryAuth = repoAuth;
    }

    @Override
    public String toString() {
        return "ContentSource{" +
                "id=" + id +
                ", org=" + org +
                ", type=" + type +
                ", label='" + label + '\'' +
                ", metadataSigned=" + metadataSigned +
                '}';
    }
}
