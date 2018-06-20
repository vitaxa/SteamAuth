package com.vitaxa.steamauth;

import com.vitaxa.steamauth.exception.WGTokenExpiredException;
import com.vitaxa.steamauth.helper.CommonHelper;
import com.vitaxa.steamauth.helper.IOHelper;
import com.vitaxa.steamauth.http.HttpParameters;
import com.vitaxa.steamauth.model.SessionData;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

public final class SteamWeb {

    private static final ThreadFactory THREAD_FACTORY = r -> CommonHelper.newThread("SteamWeb Thread", true, r);
    private static final ExecutorService THREAD_POOL = Executors.newCachedThreadPool(THREAD_FACTORY);

    private static final HttpClient httpClient = HttpClientBuilder.create().build();

    private static final HttpContext httpContext = new BasicHttpContext();

    private static CookieStore cookieStore = new BasicCookieStore();

    static {
        // Bind custom cookie store to the local context
        httpContext.setAttribute(HttpClientContext.COOKIE_STORE, cookieStore);
    }

    private SteamWeb() {
    }

    public static void addCookies(SessionData sessionData) {
        sessionData.addCookies(cookieStore);
    }

    public static void addCookies(Map<String, String> cookies) {
        for (Map.Entry<String, String> entry : cookies.entrySet()) {
            // Create cookie
            BasicClientCookie cookie = new BasicClientCookie(entry.getKey(), entry.getValue());
            cookie.setDomain(".steamcommunity.com");
            cookie.setPath("/");

            // Add cookie to cookie store
            cookieStore.addCookie(cookie);
        }
    }

    public static Future<String> asyncRequest(String url, HttpParameters params) {
        Callable<String> webRequestTask = () -> {
            return fetch(url, params);
        };

        return THREAD_POOL.submit(webRequestTask);
    }


    public static String fetch(String url, HttpParameters params) {
        return fetch(url, params, APIEndpoints.COMMUNITY_BASE, Collections.emptyMap());
    }

    public static String fetch(String url, HttpParameters params, Map<String, String> header) {
        return fetch(url, params, APIEndpoints.COMMUNITY_BASE, header);
    }

    public static String fetch(String url, HttpParameters params, String referer, Map<String, String> header) {
        String response = "";

        HttpResponse httpResponse = request(url, params, referer, header);
        try {
            HttpEntity responseEntity = httpResponse.getEntity();
            response = IOHelper.decode(IOHelper.read(responseEntity.getContent()));

            // Close connection
            EntityUtils.consume(responseEntity);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return response;
    }

    /**
     * Perform a mobile login request
     *
     * @param url    API url
     * @param method GET or POST
     */
    public static String mobileLoginRequest(String url, HttpParameters method) {
        return fetch(url, method, APIEndpoints.COMMUNITY_BASE +
                        "/mobilelogin?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client",
                Collections.emptyMap());
    }

    public static String mobileLoginRequest(String url, HttpParameters method, Map<String, String> headers) {
        return fetch(url, method, APIEndpoints.COMMUNITY_BASE +
                        "/mobilelogin?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client",
                headers);
    }

    public static HttpResponse request(String url, HttpParameters params, String referer, Map<String, String> header) {
        // Build request based on method
        switch (params.getMethod()) {
            case GET:
                HttpGet httpGet = (HttpGet) params.buildRequest(url);
                return openConnection(httpGet, HttpGet.class, referer, header);
            case POST:
                HttpPost httpPost = (HttpPost) params.buildRequest(url);
                return openConnection(httpPost, HttpPost.class, referer, header);
            case HEAD:
                HttpHead httpHead = (HttpHead) params.buildRequest(url);
                return openConnection(httpHead, HttpHead.class, referer, header);
            default:
                throw new AssertionError("Unsupported method type: " + params.getMethod().toString());
        }
    }

    public static void setCookieStore(CookieStore customCookieStore) {
        cookieStore = customCookieStore;
    }

    public static List<Cookie> getCookies() {
        return cookieStore.getCookies();
    }

    private static <T extends HttpRequestBase> HttpResponse openConnection(HttpRequestBase httpRequest, Class<T> requestType,
                                                                           String referer, Map<String, String> header) {
        T request = requestType.cast(httpRequest);
        try {
            // Add header to request
            addHeader(request, referer, header);

            // Execute request
            HttpResponse httpResponse = httpClient.execute(request, httpContext);

            try {
                handleFailedWebRequestResponse(httpResponse, httpRequest.getURI().toURL().toString());
            } catch (WGTokenExpiredException e) {
                e.printStackTrace();
            }

            return httpResponse;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void addHeader(HttpRequestBase http, String referer, Map<String, String> header) {
        http.addHeader("User-Agent", "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16" +
                " - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30");
        http.addHeader("Accept", "text/javascript, text/html, application/xml, text/xml, */*");
        http.addHeader("ContentType", "application/x-www-form-urlencoded; charset=UTF-8");
        http.addHeader("Referer", referer.isEmpty() ? "https://steamcommunity.com" : referer);

        if (!header.isEmpty())
            header.forEach(http::addHeader);
    }

    /**
     * Raise exceptions relevant to this HttpResponse -- EG, to signal that our oauth token has expired.
     */
    private static void handleFailedWebRequestResponse(HttpResponse httpResponse, String requestURL) throws WGTokenExpiredException {
        if (httpResponse == null) return;

        // Redirecting -- likely to a steammobile:// URI
        if (httpResponse.getStatusLine().getStatusCode() == HttpStatus.SC_MOVED_TEMPORARILY) {
            String location = httpResponse.getFirstHeader("Location").getValue();
            if (location != null && !location.isEmpty()) {
                // Our OAuth token has expired. This is given both when we must refresh our session,
                // or the entire OAuth Token cannot be refreshed anymore.
                // Thus, we should only throw this exception when we're attempting to refresh our session.
                if (location.equalsIgnoreCase("steammobile://lostauth") &&
                        requestURL.equalsIgnoreCase(APIEndpoints.MOBILEAUTH_GETWGTOKEN)) {
                    throw new WGTokenExpiredException("OAuth token has expired");
                }
            }
        }
    }
}
