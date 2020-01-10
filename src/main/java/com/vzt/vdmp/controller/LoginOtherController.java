package com.vzt.vdmp.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

@Controller
public class LoginOtherController {
	private static final Logger LOGGER = LoggerFactory.getLogger(LoginOtherController.class);
    private static final String FORM_VIEW = "vdmpLogin";
    private static final String SUCCESS_VIEW = "oemSelect";
    private static final String ERR_VIEW = "error";
	
	@RequestMapping(value = { "/login/other" }, method = { RequestMethod.GET })
	public String showLoginView(HttpServletRequest request,
								HttpServletResponse response) {
		return "vdmpLogin";
	}

	@RequestMapping(value = { "/secure/Other/loginSuccess" }, method = {
			RequestMethod.POST, RequestMethod.GET })
	@ResponseBody
	public String processLogin() {
		LDAPAuthentication ldap = new LDAPAuthentication();
		String uid = "user.0";
		String pwd = "@1Verizon";
        HashMap<String,Object> hm = ldap.authenricate(uid, pwd);
		return "success";
	}
	
	

}
