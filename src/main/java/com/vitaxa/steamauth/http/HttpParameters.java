package com.vitaxa.steamauth.http;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.message.BasicNameValuePair;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class HttpParameters {
    private final Map<String, String> params;
    private final HttpMethod method;

    public HttpParameters(Map<String, String> params, HttpMethod method) {
        this.params = params;
        this.method = method;
    }

    public HttpParameters(HttpMethod method) {
        this(Collections.emptyMap(), method);
    }

    public HttpRequestBase buildRequest(String url) {
        switch (method) {
            case POST:
                HttpPost httpPost = new HttpPost(url);

                // Build post params
                List<NameValuePair> urlParameters = new ArrayList<>(params.size());
                params.forEach((k, v) -> urlParameters.add(new BasicNameValuePair(k, v)));
                HttpEntity postParams = null;
                try {
                    postParams = new UrlEncodedFormEntity(urlParameters);
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }

                // Set params
                httpPost.setEntity(postParams);

                return httpPost;
            case GET:
                StringBuilder sb = new StringBuilder();

                // Add params to url
                if (!params.isEmpty()) {
                    sb.append("?");
                    buildFromParams(sb, params);
                }

                String resultUrl = url + sb.toString();

                return new HttpGet(resultUrl);
            case HEAD:
                return new HttpHead(url);
            default:
                throw new AssertionError("Unsupported method type: " + method.toString());
        }

    }

    private void buildFromParams(StringBuilder sb, Map<String, String> params) {
        for (Map.Entry<String, String> entry : params.entrySet()) {
            try {
                sb.append("&");
                sb.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
                sb.append("=");
                sb.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
    }

    public HttpMethod getMethod() {
        return method;
    }
}
