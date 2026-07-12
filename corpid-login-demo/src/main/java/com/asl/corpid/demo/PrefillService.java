package com.asl.corpid.demo;

import com.asl.corpid.helper.model.CorpidTokenResponse;

import java.util.LinkedHashMap;
import java.util.Map;

public class PrefillService {
    public Map<String, String> prefill(CorpidTokenResponse corpidToken, String selectedCompany, boolean anonymous) {
        Map<String, String> prefill = new LinkedHashMap<>();
        prefill.put("company", selectedCompany == null ? "" : selectedCompany);
        prefill.put("openId", anonymous ? "" : corpidToken == null ? "" : corpidToken.openId());
        prefill.put("userType", anonymous ? "ANON" : corpidToken == null ? "" : corpidToken.userType());
        prefill.put("scope", corpidToken == null ? "" : corpidToken.scope());
        prefill.put("prefillType", anonymous ? "anon" : "normal");
        return prefill;
    }
}