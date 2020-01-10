package com.vzt.vdmp.controller;
import java.util.HashMap;
import java.util.Hashtable;
 
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
 
public class LDAPAuthentication {
    private final String URL = "ldaps://ch2windc03p.htichina.net:636/";
    private final String BASEDN = "CN=VDMP,CN=Users,DC=htichina,DC=net";
    private final String FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    private LdapContext ctx = null;
    private final Control[] connCtls = null;
    
    private void LDAP_connect() {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, FACTORY);
        env.put(Context.PROVIDER_URL, URL + BASEDN);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
         
        String root = "CN=IAMDomainAdmin,OU=Service Accounts,OU=Service_Group,OU=Internal,OU=China,DC=htichina,DC=net";// root
        env.put(Context.SECURITY_PRINCIPAL, root);
        env.put(Context.SECURITY_CREDENTIALS, "T-systemsT-systems");
       
        try {
            ctx = new InitialLdapContext(env, connCtls);
        } catch (AuthenticationException e) {
            System.out.println("验证失败:" + e.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
 
    private HashMap<String,Object> getUserDN(String uid) {
        String userDN = "";
        HashMap<String,Object> hm = new HashMap<String,Object>();
        LDAP_connect();
        //SearchControls constraints = new SearchControls();
        try {
            /*String searchBase = "CN=Users,DC=htichina,DC=net";
            String baseDN =  "CN=VDMP,CN=Users,DC=htichina,DC=net";
            SearchControls constraints = new SearchControls();
            String searchFilter = "(&(objectCategory= CN=Person,CN=Schema,CN=Configuration,DC=htichina,DC=net)(objectClass=user))";   //user表示用户，group表示组*/

            String searchBase = "CN=Users,DC=htichina,DC=net";
            String baseDn = "CN=VDMP,CN=Users,DC=htichina,DC=net";
            // LDAP搜索过滤器类

            String searchFilter = "(&(objectCategory= CN=Person,CN=Schema,CN=Configuration,DC=htichina,DC=net)(objectClass=user)(memberof="+baseDn+")(sAMAccountName=" + uid + "))";   //user表示用户，group表示组
            // 搜索控制器
            SearchControls searchCtls = new SearchControls(); // Create the
            // 创建搜索控制器
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE); // Specify
            // 根据设置的域节点、过滤器类和搜索控制器搜索LDAP得到结果
            NamingEnumeration en = ctx.search(searchBase, searchFilter, searchCtls);// Search for objects using the filter
            // 初始化搜索结果数为0
            int totalResults = 0;// Specify the attributes to return

           /* constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            //NamingEnumeration<SearchResult> en = ctx.search(searchBase, searchFilter, constraints);*/
            if (en == null || !en.hasMoreElements()) {
                System.out.println("未找到该用户");
            }
            // maybe more than one element
            while (en != null && en.hasMoreElements()) {
                Object obj = en.nextElement();
                if (obj instanceof SearchResult) {
                    SearchResult si = (SearchResult) obj;
                    Attributes Attrs = si.getAttributes();
                    if(Attrs!=null){
                        try{
                            for(NamingEnumeration ne=Attrs.getAll();ne.hasMore();){
                                Attribute attr = (Attribute) ne.next();
                                if("uid".equals(attr.getID())){
                                    hm.put("userId", attr.get(0));
                                    userDN += si.getName();
                                    userDN += "," + BASEDN;
                                    hm.put("userDN",userDN);
                                }
                                else if("givenName".equals(attr.getID())){
                                    hm.put("firstName",attr.get(0));
                                }
                                else if("sn".equals(attr.getID())){
                                    hm.put("lastName",attr.get(0));
                                }
                                else if("mail".equals(attr.getID())){
                                    hm.put("email",attr.get(0));
                                }
                                hm.put("userRole","Administrator");
                            }
                        }
                        catch (NamingException e){
                           e.printStackTrace();
                        }
                    }
                } else {
                    System.out.println(obj);
                }
            }
        } catch (Exception e) {
            System.out.println("查找用户时产生异常");
            e.printStackTrace();
        }
 
        return hm;
    }
 
    public HashMap<String,Object> authenricate(String UID, String password) {
        boolean valide = false;
        HashMap<String,Object> hm = getUserDN(UID);
 
        try {
            ctx.addToEnvironment(Context.SECURITY_PRINCIPAL,hm.get("userDN"));
            ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
            ctx.reconnect(connCtls);
            System.out.println("验证通过");
            valide = true;
        } catch (AuthenticationException e) {
            System.out.println(" 验证失败");
            System.out.println(e.toString());
            valide = false;
        } catch (NamingException e) {
            System.out.println("验证失败");
            valide = false;
        }
        return hm;
    }
}