<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@taglib uri="http://rhn.redhat.com/rhn" prefix="rhn" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@taglib uri="http://struts.apache.org/tags-html" prefix="html" %>
<%@taglib uri="http://struts.apache.org/tags-bean" prefix="bean" %>
<%@taglib uri="http://rhn.redhat.com/tags/list" prefix="rl" %>

<html>
<body>
  <%@ include file="/WEB-INF/pages/common/fragments/ssm/header.jspf" %>
  <h2><bean:message key="ssm.errata-apply-confirm.title" /></h2>
  <p class="page-summary"><bean:message key="ssm.errata-apply-confirm.summary" /></p>

  <rl:listset name="errataSet" legend="errata">
    <rhn:csrf />
    <rhn:submitted />

<c:set var="notSelectable" value="True" />
    <div class="spacewalk-section-toolbar">
        <div class="action-button-wrapper">
            <html:submit styleClass="btn btn-primary" property="dispatch">
                <bean:message key="confirm.jsp.confirm" />
            </html:submit>
        </div>
    </div>
    <jsp:include page="/WEB-INF/pages/common/fragments/schedule-options.jspf"/>
    <%@ include file="/WEB-INF/pages/ssm/systems/errata-list-fragment.jspf" %>
  </rl:listset>
</body>
</html>
