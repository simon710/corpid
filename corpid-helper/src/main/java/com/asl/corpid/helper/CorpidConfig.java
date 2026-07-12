package com.asl.corpid.helper;

import java.nio.file.Path;
import java.util.Objects;

public final class CorpidConfig {
    private final String clientId;
    private final String clientSecret;
    private final String iamClientId;
    private final String iamClientSecret;
    private final String corpidDomain;
    private final String iamDomain;
    private final Path kekP12Path;
    private final String kekPassword;
    private final String kekPrivateKey;

    private CorpidConfig(Builder builder) {
        this.clientId = require(builder.clientId, "clientId");
        this.clientSecret = require(builder.clientSecret, "clientSecret");
        this.iamClientId = builder.iamClientId == null ? this.clientId : builder.iamClientId;
        this.iamClientSecret = builder.iamClientSecret == null ? this.clientSecret : builder.iamClientSecret;
        this.corpidDomain = normalizeDomain(require(builder.corpidDomain, "corpidDomain"));
        this.iamDomain = normalizeDomain(require(builder.iamDomain, "iamDomain"));
        String resolvedKekPrivateKey = blankToNull(builder.kekPrivateKey);
        Path resolvedKekP12Path = builder.kekP12Path;
        String resolvedKekPassword = builder.kekPassword;

        if (resolvedKekPrivateKey == null) {
            resolvedKekP12Path = Objects.requireNonNull(resolvedKekP12Path, "kekP12Path is required when KEK private key is not provided");
            resolvedKekPassword = require(resolvedKekPassword, "kekPassword");
        }

        this.kekPrivateKey = resolvedKekPrivateKey;
        this.kekP12Path = resolvedKekP12Path;
        this.kekPassword = resolvedKekPassword;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getIamClientId() {
        return iamClientId;
    }

    public String getIamClientSecret() {
        return iamClientSecret;
    }

    public String getCorpidDomain() {
        return corpidDomain;
    }

    public String getIamDomain() {
        return iamDomain;
    }

    public Path getKekP12Path() {
        return kekP12Path;
    }

    public String getKekPassword() {
        return kekPassword;
    }

    public String getKekPrivateKey() {
        return kekPrivateKey;
    }

    private static String normalizeDomain(String domain) {
        String d = domain.trim();
        if (d.startsWith("http://") || d.startsWith("https://")) {
            return d;
        }
        return "https://" + d;
    }

    private static String require(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }

    private static String blankToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }

    public static final class Builder {
        private String clientId;
        private String clientSecret;
        private String iamClientId;
        private String iamClientSecret;
        private String corpidDomain;
        private String iamDomain;
        private Path kekP12Path;
        private String kekPassword;
        private String kekPrivateKey;

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder iamClientId(String iamClientId) {
            this.iamClientId = iamClientId;
            return this;
        }

        public Builder iamClientSecret(String iamClientSecret) {
            this.iamClientSecret = iamClientSecret;
            return this;
        }

        public Builder corpidDomain(String corpidDomain) {
            this.corpidDomain = corpidDomain;
            return this;
        }

        public Builder iamDomain(String iamDomain) {
            this.iamDomain = iamDomain;
            return this;
        }

        public Builder kekP12Path(Path kekP12Path) {
            this.kekP12Path = kekP12Path;
            return this;
        }

        public Builder kekPassword(String kekPassword) {
            this.kekPassword = kekPassword;
            return this;
        }

        public Builder kekPrivateKey(String kekPrivateKey) {
            this.kekPrivateKey = kekPrivateKey;
            return this;
        }

        public CorpidConfig build() {
            return new CorpidConfig(this);
        }
    }
}
