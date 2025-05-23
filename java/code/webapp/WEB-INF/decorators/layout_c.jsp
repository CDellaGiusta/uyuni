<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"
%><%@ taglib uri="http://struts.apache.org/tags-bean" prefix="bean"
%><%@ taglib uri="http://struts.apache.org/tags-html" prefix="html"
%><%@ taglib uri="http://struts.apache.org/tags-logic" prefix="logic"
%><%@ taglib uri="http://www.opensymphony.com/sitemesh/decorator" prefix="decorator"
%><%@ taglib uri="http://www.opensymphony.com/sitemesh/page" prefix="page"
%><%@ taglib uri="http://rhn.redhat.com/rhn" prefix="rhn"
%><%@ page import="com.redhat.rhn.GlobalInstanceHolder"
%><%@ page contentType="text/html; charset=UTF-8"
%><!DOCTYPE HTML>
<html:html lang="true">
  <head>
    <jsp:include page="layout_head.jsp" />
    <decorator:head />
  </head>
  <c:set var="webTheme" value="${GlobalInstanceHolder.USER_PREFERENCE_UTILS.getCurrentWebTheme(pageContext)}"/>
  <body class="theme-${webTheme} new-theme" onload="<decorator:getProperty property="body.onload" />">
    <div class="senna-loading-bar"></div>
    <div id="menu-portal-target"></div>
    <header class="navbar-pf navbar">
      <jsp:include page="/WEB-INF/includes/header.jsp" />
    </header>
    <div class="spacewalk-main-column-layout">
      <aside id="spacewalk-aside" class="navbar-collapse collapse collapse-horizontal show">
        <div id="nav"></div>
        <jsp:include page="/WEB-INF/includes/leftnav.jsp" />
        <footer>
          <jsp:include page="/WEB-INF/includes/footer.jsp" />
        </footer>
      </aside>
      <div id="page-body">
        <section id="spacewalk-content">
          <noscript>
              <div class="alert alert-danger">
                  <bean:message key="common.jsp.noscript"/>
              </div>
          </noscript>
          <!-- Alerts and messages -->
          <logic:messagesPresent>
            <div class="alert alert-warning">
              <ul>
              <html:messages id="message">
                <li><c:out escapeXml="false" value="${message}"/></li>
              </html:messages>
              </ul>
            </div>
          </logic:messagesPresent>
          <html:messages id="message" message="true">
            <rhn:messages><c:out escapeXml="false" value="${message}" /></rhn:messages>
          </html:messages>
          <c:if test="${ not empty exception }">
            <div class="alert alert-danger">
              <c:out value="${exception}"/>
            </div>
          </c:if>
          <decorator:body />
        </section>
      </div>
      <script type="text/javascript">
        spaImportReactPage('shared/menu');
        <c:if test="${rhn:getConfig('web.spa.enable')}">
          <c:set var="spaTimeout" value="${rhn:getConfig('web.spa.timeout')}"/>
          window.pageRenderers && window.pageRenderers.spaengine.init && window.pageRenderers.spaengine.init(${spaTimeout});
        </c:if>
      </script>
    </div>
  </body>
</html:html>
