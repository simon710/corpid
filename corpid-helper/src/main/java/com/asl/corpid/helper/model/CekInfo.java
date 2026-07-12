package com.asl.corpid.helper.model;

public record CekInfo(byte[] keyBytes, long issueAt, long expiresAt) {
    public boolean isExpired(long nowMillis) {
        return nowMillis >= expiresAt;
    }
}
