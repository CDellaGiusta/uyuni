/*
 * Copyright (c) 2009--2014 Red Hat, Inc.
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
package com.redhat.rhn.frontend.servlets;

import com.redhat.rhn.frontend.context.Context;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * RhnHttpServletRequest
 */
public class RhnHttpServletRequest extends HttpServletRequestWrapper {

    private static final String ACTIVE_LANG_ATTR = "rhnActiveLang";

    private ArrayList<Locale> locales = new ArrayList<>();

    /**
     * Constructs a new RhnHttpServletRequest based on the given parameters.
     * @param request Standard HttpServletRequest which we are wrapping.
     */
    public RhnHttpServletRequest(HttpServletRequest request) {
        super(request);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getServerName() {
        String hostname = getHeader("X-Server-Hostname");
        if (hostname != null) {
            return hostname;
        }
        return super.getServerName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StringBuffer getRequestURL() {
        try {
            URL u = new URL(super.getRequestURL().toString());
            return new StringBuffer(new URL(getProtocol(),
                    getServerName(), u.getPort(), u.getFile()).toExternalForm());
        }
        catch (MalformedURLException e) {
            throw new IllegalArgumentException("Bad argument when creating URL");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getProtocol() {
        if (isSecure()) {
            return "https";
        }

        return "http";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getHeader(String name) {
        if (name.equalsIgnoreCase("Host")) {
            return getServerName();
        }
        return super.getHeader(name);
    }

    /**
     * Kind of a standard method here.
     * @return lots of information about this object in a String object.
     */
    @Override
    public String toString() {
        StringBuilder retval = new StringBuilder();

        retval.append("Local Name = ");
        retval.append(getLocalName());
        retval.append("\n");

        retval.append("Server Name = ");
        retval.append(getServerName());
        retval.append("\n");

        if (isRequestedSessionIdFromCookie()) {
            retval.append("Requested Session Id came from Cookie\n");
        }
        else if (isRequestedSessionIdFromURL()) {
            retval.append("Requested Session Id came from Url\n");
        }

        retval.append("Requested Session Valid = ");
        retval.append(isRequestedSessionIdValid());
        retval.append("\n");

        retval.append("Session = ");
        if (getSession(false) != null) {
            retval.append(ReflectionToStringBuilder.toString(getSession()));
        }
        else {
            retval.append("null");
        }
        retval.append("\n");

        retval.append("Protocol = ");
        retval.append(getProtocol());
        retval.append("\n");

        retval.append("Request Locale = ");
        retval.append(getLocale());
        retval.append("\n");

        retval.append("Request Character Encoding = ");
        retval.append(getCharacterEncoding());
        retval.append("\n");

        retval.append("Attribute Names = ");
        Enumeration<String> e = this.getAttributeNames();
        while (e.hasMoreElements()) {
            retval.append(e.nextElement());
            retval.append(", ");
        }
        retval.append("\n");

        return retval.toString();
    }

    /**
     * Returns the actual locale sent by the browser
     * @return browser's configured locale
     */
    public Locale getBrowserLocale() {
        return super.getLocale();
    }

    /**
     * Returns the list of locales sent by the browser
     * @return browser's list of configured locales
     */
    public Enumeration<Locale> getBrowserLocales() {
        return super.getLocales();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Locale getLocale() {
        return Context.getCurrentContext().getLocale();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Enumeration<Locale> getLocales() {
        return Collections.enumeration(this.locales);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getAttribute(String name) {
        if (ACTIVE_LANG_ATTR.equals(name)) {
            return Context.getCurrentContext().getActiveLocaleLabel();
        }
        return super.getAttribute(name);
    }
    /**
     * {@inheritDoc}
     */
    @Override
    public Enumeration<String> getAttributeNames() {
        ArrayList<String> tmp = new ArrayList<>();
        tmp.add(ACTIVE_LANG_ATTR);
        for (Enumeration<String> e = super.getAttributeNames(); e.hasMoreElements();) {
            tmp.add(e.nextElement());
        }
        return Collections.enumeration(tmp);
    }
    /**
     * {@inheritDoc}
     */
    @Override
    public void removeAttribute(String name) {
        if (ACTIVE_LANG_ATTR.equals(name)) {
            return;
        }
        super.removeAttribute(name);
    }
    /**
     * {@inheritDoc}
     */
    @Override
    public void setAttribute(String name, Object value) {
        if (ACTIVE_LANG_ATTR.equals(name)) {
            return;
        }
        super.setAttribute(name, value);
    }

    void configureLocale() {
        Context ctx = Context.getCurrentContext();
        Locale userLocale = ctx.getLocale();
        Enumeration<Locale> e = super.getLocales();
        while (e.hasMoreElements()) {
            Locale l = e.nextElement();
            locales.add(l);
        }
        if (!locales.contains(userLocale)) {
            locales.add(0, userLocale);
        }

    }
}
