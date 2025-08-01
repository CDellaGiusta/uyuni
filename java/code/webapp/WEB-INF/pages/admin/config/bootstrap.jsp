<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://rhn.redhat.com/rhn" prefix="rhn" %>
<%@ taglib uri="http://struts.apache.org/tags-bean" prefix="bean" %>
<%@ taglib uri="http://struts.apache.org/tags-html" prefix="html" %>

<html:html>
    <body>
        <rhn:toolbar base="h1" icon="header-info" imgAlt="info.alt.img"
                     helpUrl="/docs/${rhn:getDocsLocale(pageContext)}/reference/admin/bootstrap-script.html">
            <bean:message key="bootstrap.jsp.toolbar"/>
        </rhn:toolbar>
        <p><bean:message key="bootstrap.jsp.summary"/></p>
        <rhn:dialogmenu mindepth="0" maxdepth="1" definition="/WEB-INF/nav/sat_config.xml" renderer="com.redhat.rhn.frontend.nav.DialognavRenderer" />
        <div class="panel panel-default">
            <div class="panel-heading">
                <h4><bean:message key="bootstrap.jsp.header2"/></h4>
            </div>
            <div class="panel-body">
                <html:form action="/admin/config/BootstrapConfig?csrf_token=${csrfToken}"
                           styleClass="form-horizontal"
                           enctype="multipart/form-data">
                    <rhn:csrf />
                    <div class="form-group">
                        <label for="hostname" class="col-lg-3 control-label">
                            <rhn:required-field key="bootstrap.jsp.hostname"/>
                        </label>
                        <div class="col-lg-6">
                            <html:text size="32" property="hostname" styleId="hostname" styleClass="form-control" />
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="col-lg-3 control-label" for="ssl-cert">
                            <rhn:required-field key="bootstrap.jsp.ssl-cert"/>
                        </label>
                        <div class="col-lg-6">
                            <html:text size="32" property="ssl-cert" styleId="ssl-cert" styleClass="form-control" />
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="col-lg-3 control-label" for="gpg">
                            <bean:message key="bootstrap.jsp.gpg"/>
                        </label>
                        <div class="col-lg-6">
                            <div class="checkbox">
                                    <html:checkbox property="gpg" styleId="gpg" />
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="col-lg-3 control-label" for="http-proxy">
                            <bean:message key="bootstrap.jsp.http-proxy"/>
                        </label>
                        <div class="col-lg-6">
                            <html:text size="32" property="http-proxy" styleId="http-proxy" styleClass="form-control" />
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="http-proxy-username" class="col-lg-3 control-label">
                            <bean:message key="bootstrap.jsp.http-proxy-username"/>
                        </label>
                        <div class="col-lg-6">
                            <html:text size="32" property="http-proxy-username" styleClass="form-control" styleId="http-proxy-username" />
                        </div>
                    </div>
                    <div class="form-group">
                        <div class="col-lg-offset-3 offset-lg-3 col-lg-6">
                            <html:submit styleClass="btn btn-primary">
                                <bean:message key="config.update"/>
                            </html:submit>
                        </div>
                    </div>
                    <html:hidden property="submitted" value="true"/>
                </html:form>
            </div>
        </div>
    </body>
</html:html>

