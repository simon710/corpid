package com.asl.corpid.helper.model;

public record IamTokenResponse(
        String accessToken,
        String tokenType,
        long issueAt,
        long expiresIn,
        String openId,
        String scope,
        String rawContentJson
) {
}
