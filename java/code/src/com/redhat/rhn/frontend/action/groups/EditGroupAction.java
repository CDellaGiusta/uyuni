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

package com.redhat.rhn.frontend.action.groups;

import com.redhat.rhn.GlobalInstanceHolder;
import com.redhat.rhn.domain.server.ManagedServerGroup;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.server.ServerFactory;
import com.redhat.rhn.domain.server.ServerGroupFactory;
import com.redhat.rhn.frontend.dto.SystemOverview;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.frontend.struts.RhnHelper;
import com.redhat.rhn.manager.rhnset.RhnSetDecl;
import com.redhat.rhn.manager.system.ServerGroupManager;
import com.redhat.rhn.manager.system.SystemManager;

import org.apache.commons.lang3.StringUtils;
import org.apache.struts.action.ActionErrors;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.apache.struts.action.ActionMessage;
import org.apache.struts.action.ActionMessages;
import org.apache.struts.action.DynaActionForm;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * @author paji
 */
public class EditGroupAction extends RhnAction {

    private static final ServerGroupManager SERVER_GROUP_MANAGER = GlobalInstanceHolder.SERVER_GROUP_MANAGER;

    /** {@inheritDoc} */
    @Override
    public ActionForward execute(ActionMapping mapping,
                                 ActionForm form,
                                 HttpServletRequest request,
                                 HttpServletResponse response) {

        DynaActionForm daForm = (DynaActionForm)form;
        ActionErrors errors = new ActionErrors();
        Map<String, Object> params = makeParamMap(request);
        RequestContext ctx = new RequestContext(request);

        if (ctx.hasParam("sgid")) {
            params.put("sgid", ctx.getParam("sgid", true));
        }

        if (!isSubmitted(daForm)) {
            setupForm(request, daForm);
            return getStrutsDelegate().forwardParams(
                    mapping.findForward(RhnHelper.DEFAULT_FORWARD),
                    params);
        }

        // process values - create or update
        if (ctx.hasParam("create_button")) {
            Long sgid = create(daForm, errors, ctx);
            params.put("sgid", sgid);
        }
        else if (ctx.hasParam("edit_button")) {
            edit(daForm, errors, ctx);
        }

        if (!errors.isEmpty()) {
            addErrors(request, errors);
            request.setAttribute("name", daForm.get("name"));
            request.setAttribute("description", daForm.get("description"));
            return getStrutsDelegate().forwardParams(
                    mapping.findForward(RhnHelper.DEFAULT_FORWARD),
                    params);
        }

        if (ctx.hasParam("create_button")) {
            createSuccessMessage(request,
                    "systemgroups.create.successmessage", daForm.getString("name"));
        }
        else if (ctx.hasParam("edit_button")) {
            createSuccessMessage(request,
                    "systemgroups.edit.successmessage", daForm.getString("name"));
        }

        return getStrutsDelegate().forwardParams(
                mapping.findForward("success"), params);
    }

    private void setupForm(HttpServletRequest request, DynaActionForm form) {

        RequestContext ctx = new RequestContext(request);
        Long sgid = ctx.getParamAsLong("sgid");

        // editing form - prefill values
        if (sgid != null) {
            ManagedServerGroup sg = ctx.lookupAndBindServerGroup();
            form.set("name", sg.getName());
            form.set("description", sg.getDescription());
        }
    }

    private Long create(DynaActionForm form, ActionErrors errors,
            RequestContext ctx) {

        validate(form, errors, ctx);

        if (errors.isEmpty()) {
            ManagedServerGroup sg = SERVER_GROUP_MANAGER.create(ctx.getCurrentUser(),
                    form.getString("name"), form.getString("description"));

            if (form.get("is_ssm") != null && (Boolean)form.get("is_ssm")) {
                List<SystemOverview> systems = SystemManager.inSet(ctx.getCurrentUser(),
                        RhnSetDecl.SYSTEMS.getLabel());
                List<Server> hibernateServers = new ArrayList<>();
                for (SystemOverview system : systems) {
                    hibernateServers.add(ServerFactory.lookupById(system.getId()));
                }
                SERVER_GROUP_MANAGER.addServers(sg, hibernateServers, ctx.getCurrentUser());
            }

            return sg.getId();
        }

        return null;
    }

    private void edit(DynaActionForm form, ActionErrors errors,
            RequestContext ctx) {

        validate(form, errors, ctx);

        if (errors.isEmpty()) {
            ManagedServerGroup sg = ctx.lookupAndBindServerGroup();
            sg.setName(form.getString("name"));
            sg.setDescription(form.getString("description"));
            ServerGroupFactory.save(sg);
        }
    }

    private void validate(DynaActionForm form, ActionErrors errors,
            RequestContext ctx) {

        String name = form.getString("name");
        String desc = form.getString("description");
        Long sgid = ctx.getParamAsLong("sgid");

        // Check if both values are entered
        if (StringUtils.isEmpty(name) || StringUtils.isEmpty(desc)) {
            errors.add(ActionMessages.GLOBAL_MESSAGE,
                    new ActionMessage("systemgroup.create.requirements"));
        }

        // Check if sg already exists
        ManagedServerGroup newGroup = ServerGroupFactory.lookupByNameAndOrg(name,
                ctx.getCurrentUser().getOrg());

        // Ugly condition for two error cases:
        //     creating page + group name exists
        //     editing page + group name exists except our group
        if (((sgid == null) && (newGroup != null)) ||
                (sgid != null) && (newGroup != null) && (!sgid.equals(newGroup.getId()))) {
            errors.add(ActionMessages.GLOBAL_MESSAGE,
                    new ActionMessage("systemgroup.create.alreadyexists"));
        }

    }

}
