package com.asl.corpid.demo;

import com.asl.corpid.helper.model.CorpidTokenResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

public class SelectCompanyService {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public SelectCompanyDecision buildDecision(CorpidTokenResponse corpidToken) {
        int corpCount = extractCorpCount(corpidToken);
        if (corpCount <= 1) {
            return new SelectCompanyDecision(corpCount, false, "Company 1", List.of("Company 1"));
        }

        List<String> options = new ArrayList<>();
        for (int i = 1; i <= corpCount; i++) {
            options.add("Company " + i);
        }
        return new SelectCompanyDecision(corpCount, true, "", options);
    }

    private int extractCorpCount(CorpidTokenResponse corpidToken) {
        if (corpidToken == null || corpidToken.rawContentJson() == null || corpidToken.rawContentJson().isBlank()) {
            return 1;
        }
        try {
            JsonNode root = MAPPER.readTree(corpidToken.rawContentJson());
            int corpCount = root.path("corpCount").asInt(1);
            return Math.max(1, corpCount);
        } catch (Exception ex) {
            return 1;
        }
    }

    public record SelectCompanyDecision(
            int corpCount,
            boolean requiresSelection,
            String selectedCompany,
            List<String> companyOptions
    ) {
    }
}