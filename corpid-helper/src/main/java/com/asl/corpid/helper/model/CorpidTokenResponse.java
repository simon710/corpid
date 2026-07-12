package com.asl.corpid.helper.model;

public record CorpidTokenResponse(
        String accessToken,
        String tokenType,
        long issueAt,
        long expiresIn,
        String openId,
        String userType,
        String scope,
        String rawContentJson
) {
}
