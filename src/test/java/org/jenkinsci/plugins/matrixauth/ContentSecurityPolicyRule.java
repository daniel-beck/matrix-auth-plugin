package org.jenkinsci.plugins.matrixauth;

import static org.hamcrest.MatcherAssert.*;
import static org.hamcrest.Matchers.empty;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.InvisibleAction;
import hudson.model.PageDecorator;
import hudson.model.UnprotectedRootAction;
import hudson.security.csrf.CrumbExclusion;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.sf.json.JSONObject;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.junit.rules.Verifier;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.kohsuke.stapler.Ancestor;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.POST;

public class ContentSecurityPolicyRule extends Verifier {
    private ContentSecurityPolicyRule() {
        // Require use of #create
    }

    public static ContentSecurityPolicyRule create() {
        return new ContentSecurityPolicyRule();
    }

    @Override
    public Statement apply(Statement base, Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                base.evaluate();
                assertThat(ContentSecurityPolicyRootAction.reports, empty());
            }
        };
    }

    @Extension
    public static class ContentSecurityPolicyRootAction extends InvisibleAction implements UnprotectedRootAction {
        private static final class Report {
            String objectClass;
            String view;
            JSONObject json;

            private Report(String objectClass, String view, JSONObject json) {
                this.objectClass = objectClass;
                this.view = view;
                this.json = json;
            }

            @Override
            public String toString() {
                try {
                    final String blockedUri = json.getJSONObject("csp-report").getString("blocked-uri");
                    final String violatedDirective = json.getJSONObject("csp-report").getString("violated-directive");
                    return "Ancestor Object[" + objectClass + "]; View[" + view + "]; Violated Directive[" + violatedDirective + "]; Blocked URI[" + blockedUri + "]";
                } catch (Exception ex) {
                    // Something went wrong with JSON, return raw
                    return "Ancestor Object[" + objectClass + "]; View[" + view + "]; JSON: " + json;
                }
            }
        }

        /**
         * Hold reported CSP violations. static to survive Jenkins shutdown at end of test; constructor resets it.
         */
        private static final Collection<Report> reports = new ArrayList<>();

        protected static final String URL = "jenkins-test-harness-content-security-policy-rule";
        public static final Logger LOGGER = Logger.getLogger(ContentSecurityPolicyRootAction.class.getName());

        public ContentSecurityPolicyRootAction() {
            reports.clear();
        }

        @Override
        public String getUrlName() {
            return URL;
        }

        @POST
        public HttpResponse doDynamic(StaplerRequest req) {
            String restOfPath = StringUtils.removeStart(req.getRestOfPath(), "/");

            try {
                try (Reader reader = req.getReader()) {
                    String jsonString = IOUtils.toString(reader);
                    final JSONObject jsonObject = JSONObject.fromObject(jsonString);

                    final List<String> parts = Arrays.stream(restOfPath.split(":"))
                            .map(ContentSecurityPolicyDecorator::fromBase64)
                            .collect(Collectors.toList());
                    final Report report = new Report(parts.get(0), parts.get(1), jsonObject);
                    reports.add(report);
                    LOGGER.log(Level.FINE, "Recording " + report);
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, e, () -> "Failed to read request body for /" + URL + "/" + restOfPath);
                }
                return HttpResponses.ok();
            } catch (RuntimeException ex) {
                LOGGER.log(
                        Level.FINE,
                        "Unexpected rest of path failed to decode: " + restOfPath + " with exception: "
                                + ex.getMessage());
                return HttpResponses.ok();
            }
        }

        @Extension
        public static class CrumbExclusionImpl extends CrumbExclusion {
            @Override
            public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                    throws IOException, ServletException {
                String pathInfo = request.getPathInfo();
                if (pathInfo != null && pathInfo.startsWith("/" + URL + "/")) {
                    chain.doFilter(request, response);
                    return true;
                }
                return false;
            }
        }
    }

    @Extension
    public static class ContentSecurityPolicyDecorator extends PageDecorator {
        public String getHeader() {
            return "Content-Security-Policy-Report-Only";
        }

        public String getValue(String rootURL) {
            return "default-src 'none'; report-uri " + rootURL + "/" + ContentSecurityPolicyRootAction.URL + "/"
                    + getContext();
        }

        private static String getContext() {
            final List<Ancestor> ancestors = Stapler.getCurrentRequest().getAncestors();
            if (ancestors.isEmpty()) {
                // probably doesn't happen?
                return "";
            }
            Ancestor nearest = ancestors.get(ancestors.size() - 1);
            Object nearestObjectName = nearest.getObject().getClass().getName();
            String restOfUrl = nearest.getRestOfUrl();

            return encodeContext(nearestObjectName, restOfUrl);
        }

        private static String encodeContext(@NonNull final Object ancestorName, @NonNull final String restOfPath) {
            return toBase64(ancestorName.toString()) + ":" + toBase64(restOfPath);
        }

        private static String toBase64(String utf8) {
            return Base64.getUrlEncoder().encodeToString(utf8.getBytes(StandardCharsets.UTF_8));
        }

        private static String fromBase64(String b64) {
            return new String(Base64.getUrlDecoder().decode(b64), StandardCharsets.UTF_8);
        }
    }
}
