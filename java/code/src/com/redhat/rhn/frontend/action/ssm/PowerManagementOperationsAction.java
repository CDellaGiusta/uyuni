/*
 * Copyright (c) 2013 SUSE LLC
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
package com.redhat.rhn.frontend.action.ssm;

import com.redhat.rhn.common.localization.LocalizationService;
import com.redhat.rhn.common.messaging.MessageQueue;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.action.kickstart.PowerManagementAction;
import com.redhat.rhn.frontend.dto.SystemOverview;
import com.redhat.rhn.frontend.events.SsmPowerManagementEvent;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.frontend.struts.RhnHelper;
import com.redhat.rhn.frontend.struts.StrutsDelegate;
import com.redhat.rhn.frontend.taglibs.list.helper.ListHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.Listable;
import com.redhat.rhn.manager.entitlement.EntitlementManager;
import com.redhat.rhn.manager.kickstart.cobbler.CobblerPowerCommand.Operation;
import com.redhat.rhn.manager.rhnset.RhnSetDecl;
import com.redhat.rhn.manager.system.SystemManager;
import com.redhat.rhn.taskomatic.TaskomaticApi;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.struts.action.ActionErrors;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

import java.util.LinkedList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Powers on, off and reboots multiple systems.
 * @author Silvio Moioli {@literal <smoioli@suse.de>}
 */
public class PowerManagementOperationsAction extends RhnAction implements
        Listable<SystemOverview> {

    /** Logger instance */
    private static Logger log = LogManager.getLogger(PowerManagementOperationsAction.class);

    /** Taskomatic API instance */
    private static final TaskomaticApi TASKOMATIC_API = new TaskomaticApi();

    /**
     * Runs this action.
     * @param mapping action mapping
     * @param formIn form submitted values
     * @param request http request object
     * @param response http response object
     * @return an action forward object
     */
    @Override
    public ActionForward execute(ActionMapping mapping, ActionForm formIn,
        HttpServletRequest request, HttpServletResponse response) {
        RequestContext context = new RequestContext(request);
        StrutsDelegate strutsDelegate = getStrutsDelegate();
        User user = context.getCurrentUser();
        ActionErrors errors = new ActionErrors();

        if (context.isSubmitted()) {
            // Is taskomatic running?
            if (!TASKOMATIC_API.isRunning()) {
                log.error("Cannot schedule action: Taskomatic is not running");
                getStrutsDelegate().addError("taskscheduler.down", errors);
                getStrutsDelegate().saveMessages(request, errors);
                return mapping.findForward(RhnHelper.DEFAULT_FORWARD);
            }

            List<SystemOverview> systemOverviews = getResult(context);

            Operation operation = null;
            if (context.wasDispatched(
                "kickstart.powermanagement.jsp.power_on")) {
                operation = Operation.POWER_ON;
            }
            if (context.wasDispatched(
                "kickstart.powermanagement.jsp.power_off")) {
                operation = Operation.POWER_OFF;
            }
            if (context.wasDispatched(
                "kickstart.powermanagement.jsp.reboot")) {
                operation = Operation.REBOOT;
            }

            if (operation != null) {
                MessageQueue.publish(new SsmPowerManagementEvent(user.getId(),
                    systemOverviews, operation));

                String[] messageParams = {
                    "" + systemOverviews.size(),
                    LocalizationService.getInstance().getPlainText(
                            "cobbler.powermanagement." +
                                operation.toString().toLowerCase()).toLowerCase()
                };

                createMessage(request, "ssm.provisioning.powermanagement.operations.saved",
                    messageParams);
            }
        }

        PowerManagementAction.setUpPowerTypes(request, strutsDelegate, errors);

        ListHelper helper = new ListHelper(this, request);
        helper.execute();

        return strutsDelegate.forwardParams(mapping.findForward(RhnHelper.DEFAULT_FORWARD),
            request.getParameterMap());
    }

    /**
     * ${@inheritDoc}
     */
    @Override
    public List<SystemOverview> getResult(RequestContext context) {
        User user = context.getCurrentUser();
        return SystemManager.entitledInSet(user, RhnSetDecl.SYSTEMS.getLabel(),
                new LinkedList<>() {
                    {
                        add(EntitlementManager.BOOTSTRAP_ENTITLED);
                        add(EntitlementManager.ENTERPRISE_ENTITLED);
                        add(EntitlementManager.SALT_ENTITLED);
                    }
                });
    }
}
