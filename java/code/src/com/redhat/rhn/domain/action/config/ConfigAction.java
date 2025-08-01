/*
 * Copyright (c) 2009--2015 Red Hat, Inc.
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
package com.redhat.rhn.domain.action.config;

import com.redhat.rhn.common.localization.LocalizationService;
import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.action.ActionFormatter;
import com.redhat.rhn.domain.server.MinionSummary;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.html.HtmlTag;

import com.suse.salt.netapi.calls.LocalCall;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * ConfigAction
 */
public class ConfigAction extends Action {
    private Set<ConfigRevisionAction> configRevisionActions;

    protected ConfigAction() {
        //ConfigAction should never be instantiated
        //instead, one of ConfigDiffAction, ConfigDeployAction,ConfigVerifyAction classes should
    }

    /**
     * @return Returns the configRevisionActions.
     */
    public Set<ConfigRevisionAction> getConfigRevisionActions() {
        return configRevisionActions;
    }
    /**
     * @param configRevisionActionsIn The configRevisionActions to set.
     */
    public void setConfigRevisionActions(Set<ConfigRevisionAction>
                                            configRevisionActionsIn) {
        this.configRevisionActions = configRevisionActionsIn;
    }

    /**
     * Add a ConfigRevisionAction to the collection.
     * @param crIn the ConfigRevisionAction to add
     */
    public void addConfigRevisionAction(ConfigRevisionAction crIn) {
        if (configRevisionActions == null) {
            configRevisionActions = new HashSet<>();
        }
        crIn.setParentAction(this);
        configRevisionActions.add(crIn);
    }

    /**
     * Get the Formatter for this class but in this case we use
     * ConfigActionFormatter.
     *
     * {@inheritDoc}
     */
    @Override
    public ActionFormatter getFormatter() {
        if (formatter == null) {
            formatter = new ConfigActionFormatter(this);
        }
        return formatter;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getHistoryDetails(Server server, User currentUser) {
        LocalizationService ls = LocalizationService.getInstance();
        StringBuilder retval = new StringBuilder();
        retval.append("</br>");
        retval.append(ls.getMessage("system.event.configFiles"));
        retval.append("</br>");
        for (ConfigRevisionAction rev : this.getConfigRevisionActionsSorted()) {
            if (rev.getServer().equals(server)) {
                HtmlTag a = new HtmlTag("a");
                a.setAttribute("href", "/rhn/configuration/file/FileDetails.do?sid=" +
                        server.getId().toString() + "&crid=" +
                        rev.getConfigRevision().getId());
                a.addBody(rev.getConfigRevision().getConfigFile().getConfigFileName()
                        .getPath());
                retval.append(a.render());
                retval.append(" (rev. " + rev.getConfigRevision().getRevision() + ")");
                retval.append("</br>");
            }
        }
        return retval.toString();
    }

    /**
     * Sort the set of revision actions for their config file paths.
     * @return sorted list of revision actions
     */
    protected List<ConfigRevisionAction> getConfigRevisionActionsSorted() {
        List<ConfigRevisionAction> revisionActions = new ArrayList<>(
                this.getConfigRevisionActions());
        revisionActions.sort((o1, o2) -> {
            String p1 = o1.getConfigRevision().getConfigFile().
                    getConfigFileName().getPath();
            String p2 = o2.getConfigRevision().getConfigFile().
                    getConfigFileName().getPath();
            return p1.compareTo(p2);
        });
        return Collections.unmodifiableList(revisionActions);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<LocalCall<?>, List<MinionSummary>> getSaltCalls(List<MinionSummary> minionSummaries) {
        //ConfigAction should never be instantiated
        //instead, one of ConfigDiffAction, ConfigDeployAction,ConfigVerifyAction classes should
        throw new IllegalStateException("SHOULDN'T BE HERE: ConfigAction::getSaltCalls");
    }
}
