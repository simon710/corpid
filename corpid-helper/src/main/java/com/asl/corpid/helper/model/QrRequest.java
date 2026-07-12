package com.asl.corpid.helper.model;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public final class QrRequest {
    private final String responseType;
    private final String source;
    private final String redirectUri;
    private final String scope;
    private final String cScope;
    private final String ticketId;
    private final String lang;
    private final String state;
    private final Boolean brokerPage;

    private QrRequest(Builder builder) {
        this.responseType = builder.responseType == null ? "code" : builder.responseType;
        this.source = required(builder.source, "source");
        this.redirectUri = required(builder.redirectUri, "redirectUri");
        this.scope = required(builder.scope, "scope");
        this.cScope = builder.cScope;
        this.ticketId = builder.ticketId;
        this.lang = builder.lang == null ? "en-US" : builder.lang;
        this.state = builder.state;
        this.brokerPage = builder.brokerPage;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String toQueryString(String clientId) {
        StringBuilder sb = new StringBuilder();
        append(sb, "clientID", clientId);
        append(sb, "source", source);
        if (brokerPage != null) {
            appendRaw(sb, "brokerPage", brokerPage ? "True" : "False");
        }
        append(sb, "responseType", responseType);
        append(sb, "redirectURI", redirectUri);
        append(sb, "scope", scope);
        if (cScope != null && !cScope.isBlank()) {
            append(sb, "cScope", cScope);
        }
        if (state != null && !state.isBlank()) {
            append(sb, "state", state);
        }
        if (ticketId != null && !ticketId.isBlank()) {
            append(sb, "ticketID", ticketId);
        }
        append(sb, "lang", lang);
        return sb.substring(1);
    }

    private static void append(StringBuilder sb, String key, String value) {
        sb.append('&')
                .append(key)
                .append('=')
                .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
    }

    private static void appendRaw(StringBuilder sb, String key, String value) {
        sb.append('&')
                .append(key)
                .append('=')
                .append(value);
    }

    private static String required(String value, String field) {
        Objects.requireNonNull(value, field + " is required");
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }

    public static final class Builder {
        private String responseType;
        private String source;
        private String redirectUri;
        private String scope;
        private String cScope;
        private String ticketId;
        private String lang;
        private String state;
        private Boolean brokerPage;

        public Builder responseType(String responseType) {
            this.responseType = responseType;
            return this;
        }

        public Builder source(String source) {
            this.source = source;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder cScope(String cScope) {
            this.cScope = cScope;
            return this;
        }

        public Builder ticketId(String ticketId) {
            this.ticketId = ticketId;
            return this;
        }

        public Builder lang(String lang) {
            this.lang = lang;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder brokerPage(boolean brokerPage) {
            this.brokerPage = brokerPage;
            return this;
        }

        public Builder brokerPage(Boolean brokerPage) {
            this.brokerPage = brokerPage;
            return this;
        }

        public QrRequest build() {
            return new QrRequest(this);
        }
    }
}
