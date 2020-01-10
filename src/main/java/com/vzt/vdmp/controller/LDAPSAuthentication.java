package com.vzt.vdmp.controller;

import java.util.Enumeration;
import java.util.Hashtable;
 
import java.util.Properties;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
 
public class LDAPSAuthentication {
    private final String URL = "ldaps://ch2windc03p.htichina.net:636/";
    private final String BASEDN = "ou=People,dc=example,dc=com";
    private final String FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    private LdapContext ctx = null;
    private final Control[] connCtls = null;
    
    private void LDAPS_connect() {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, FACTORY);
        env.put(Context.PROVIDER_URL, URL + BASEDN);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        String root = "CN=IAMDomainAdmin,OU=Service Accounts,OU=Service_Group,OU=Internal,OU=China,DC=htichina,DC=net";  // 根，根据自己情况修改
        env.put(Context.SECURITY_PRINCIPAL, root);   // 管理员
        env.put(Context.SECURITY_CREDENTIALS, "T-systemsT-systems");  // 管理员密码

        try {
            ctx = new InitialLdapContext(env, connCtls);
            System.out.println( "认证成功" );
            System.out.println(ctx);
            getUserInfo();
        } catch (javax.naming.AuthenticationException e) {
            System.out.println("认证失败：");
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println("认证出错：");
            e.printStackTrace();
        }

        /*if (ctx != null) {
            try {
                ctx.close();
            }
            catch (NamingException e) {
                e.printStackTrace();
            }

        }*/
    }

    /**
     * 遍历AD域
     *
     * @throws NamingException
     */
    private void getUserInfo() throws NamingException {
        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        // 注意OU和DC的先后顺序
        NamingEnumeration results = this.ctx.search("CN=VDMP,CN=Users,DC=htichina,DC=net", "objectClass=User", searchCtls);

        while (results.hasMoreElements()) {
            SearchResult sr = (SearchResult) results.next();
            Attributes attributes = sr.getAttributes();
            NamingEnumeration values = attributes.getAll();
            while (values.hasMore()) {
                Attribute attr = (Attribute) values.next();
                Enumeration vals = attr.getAll();
                while (vals.hasMoreElements()) {
                    Object o = vals.nextElement();
                    System.out.println(attr.getID() + "--------------" + o.toString());
                }
            }
        }
    }

    private void getUserDN(String uid) {
        String userDN = "";
        LDAPS_connect();
        try {
            getUserInfo();
        } catch (NamingException e) {
            e.printStackTrace();
        }
        /*try {
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> en = ctx.search("", "uid=" + uid, constraints);
            if (en == null || !en.hasMoreElements()) {
                System.out.println("未找到该用户");
            }
            // maybe more than one element
            while (en != null && en.hasMoreElements()) {
                Object obj = en.nextElement();
                if (obj instanceof SearchResult) {
                    SearchResult si = (SearchResult) obj;
                    userDN += si.getName();
                    userDN += "," + BASEDN;
                } else {
                    System.out.println(obj);
                }
            }
        } catch (Exception e) {
            System.out.println("查找用户时产生异常。");
            e.printStackTrace();
        }
 
        return userDN;*/
    }
 
    public boolean authenricate(String UID, String password) {
        boolean valide = false;
        getUserDN(UID);
 
        /*try {
            ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, userDN);
            ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
            ctx.reconnect(connCtls);
            System.out.println(userDN + " success");
            valide = true;
        } catch (AuthenticationException e) {
            System.out.println(userDN + " fail1");
            System.out.println(e.toString());
            valide = false;
        } catch (NamingException e) {
            System.out.println(userDN + " fail2");
            valide = false;
        }*/
 
        return valide;
    }
}