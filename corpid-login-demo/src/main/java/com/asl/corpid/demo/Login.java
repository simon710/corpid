package com.asl.corpid.demo;

import com.asl.corpid.helper.CorpidConfig;

public class Login {
    public static void main(String[] args) throws Exception {
        CorpidConfig config = LoginService.importConfig();
        LoginService.login(config);
    }
}
