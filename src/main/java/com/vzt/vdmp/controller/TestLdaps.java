package com.vzt.vdmp.controller;

import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.*;

public class TestLdaps {
    /**
     *
     * @return void
     * @throws
     * @param username
     * @param password
     */
    public HashMap<String,Object> authenricate(String username,String password) {
        HashMap<String,Object> hm = new HashMap<String,Object>();
        DirContext ctx=null;
        String company = "";
        String domainUser="CN=IAMDomainAdmin,OU=Service Accounts,OU=Service_Group,OU=Internal,OU=China,DC=htichina,DC=net";
        String domainPwd="T-systemsT-systems";
        String confingBaseDn = "CN=VDMP-BWDa,OU=Leave,OU=Internal,OU=China,DC=htichina,DC=net";
        Hashtable<String,String> HashEnv = new Hashtable<String,String>();
        HashEnv.put(Context.SECURITY_AUTHENTICATION, "simple"); //
        HashEnv.put(Context.SECURITY_PRINCIPAL, username); //
        HashEnv.put(Context.SECURITY_CREDENTIALS, password); //
        HashEnv.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory"); //
        HashEnv.put("com.sun.jndi.ldap.connect.timeout", "3000");//
        HashEnv.put(Context.PROVIDER_URL, "ldaps://ch2windc03p.htichina.net:636/");//
        try {
            System.out.println(HashEnv.toString());
            ctx = new InitialDirContext(HashEnv);//
            System.out.println("success!!!!!!!!!!");

            String searchBase = "OU=Leave,OU=Internal,OU=China,DC=htichina,DC=net";
            String baseDn = "CN=VDMP-BWDa,OU=Leave,OU=Internal,OU=China,DC=htichina,DC=net";

            String searchFilter = "(&(objectCategory= CN=Person,CN=Schema,CN=Configuration,DC=htichina,DC=net)(objectClass=user)(memberof="+baseDn+")(sAMAccountName=" + username + "))";
            SearchControls searchCtls = new SearchControls(); // Create the

            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE); // Specify

            NamingEnumeration answer = ctx.search(searchBase, searchFilter, searchCtls);// Search for objects using the filter
            //
            int totalResults = 0;// Specify the attributes to return
            int rows = 0;
            while (answer.hasMoreElements()) {//
                String uName= "";
                SearchResult sr = (SearchResult) answer.next();//
                String dn = sr.getName();

                Attributes Attrs = sr.getAttributes();//
                if (Attrs != null) {
                    try {
                        for (NamingEnumeration ne = Attrs.getAll(); ne.hasMore();) {
                            Attribute Attr = (Attribute) ne.next();//
                            for (NamingEnumeration e = Attr.getAll(); e.hasMore(); totalResults++) {
                                company = e.next().toString();
                                System.out.println("Attr.getID().toString()=="+Attr.getID().toString()+"====="+company);
                                if("memberof".equals(Attr.getID().toString().toLowerCase()) && company.indexOf(confingBaseDn)>=0){
                                    hm.put("memberOf", confingBaseDn);
                                }
                                else if("memberof".equals(Attr.getID().toString().toLowerCase()) && company.indexOf(confingBaseDn)<0){
                                    continue;
                                }
                                else {
                                    hm.put(Attr.getID().toString(), company);
                                }
                                System.out.println(" AttributeID=属性名：" + Attr.getID().toString());
                                System.out.println("value==" + company);
                            }
                        }
                    } catch (NamingException e) {
                        System.err.println("Throw Exception : " + e);
                    }
                }
                System.out.println("Number: " + totalResults);
                if(hm!=null && hm.size()>0 && (!"CN=VDMP-BWDa,OU=Leave,OU=Internal,OU=China,DC=htichina,DC=net".equals(hm.get("memberOf")) || !"CN=VDMP-BWDa,OU=Leave,OU=Internal,OU=China,DC=htichina,DC=net".equals(hm.get("memberOf")))){
                    return null;
                }
            }
            System.out.println("success!!!!!!!!333333");
        } catch (AuthenticationException e) {
            System.out.println("success!");
            e.printStackTrace();
        } catch (javax.naming.CommunicationException e) {
            System.out.println("AD fail!");
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println("undefined");
            e.printStackTrace();
        } finally{
            if(null!=ctx){
                try {
                    ctx.close();
                    ctx=null;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }




        return hm;
    }

    public static void main(String[] args) {
        TestLdaps demo = new TestLdaps();
        demo.authenricate("vdmptest10", "BwdaBwda1234!@#");
        //String ss = Base64.getEncoder().encodeToString("BwdaBwda123!@#".getBytes());
        //String decodeStr = new String(Base64.getDecoder().decode("cGFzc3dvcmQ="));
        //System.out.println("BwdaBwda123!@#".getBytes()+"===="+ss+"===="+decodeStr);
    }
}


//cGFzc3dvcmQ=







