package com.vzt.vdmp.controller;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;

public class LdapsAuthenticationTool {
    public static void readLdap(String userName){

        Hashtable<String, String> env = new Hashtable<String, String>();
        DirContext ctx = null;
        env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldaps://ch2windc03p.htichina.net:636/CN=VDMP,CN=Users,DC=htichina,DC=net");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "bwdatest4");
        env.put(Context.SECURITY_CREDENTIALS, "BwdaBwda123!@#");
        try {
            ctx = new InitialDirContext(env);
        } catch (NamingException e) {
            e.printStackTrace();
            return;
        }

        Map<String,String> map = new HashMap<String, String>();
        try {
            if (ctx != null) {
                // 域节点
                String searchBase = "CN=Users,DC=htichina,DC=net";
                String baseDN =  "CN=VDMP,CN=Users,DC=htichina,DC=net";
                String searchFilter = "(&(objectCategory= CN=Person,CN=Schema,CN=Configuration,DC=htichina,DC=net)(objectClass=user)(memberof="+baseDN+")(sAMAccountName=" + userName + "))";   //user表示用户，group表示组
                // 搜索控制器
                SearchControls searchCtls = new SearchControls(); // Create the
                // 创建搜索控制器
                searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE); // Specify
                //String returnedAtts[] = {"memberOf",""sAMAccountName", "cloudExtensionAttribute"};// 定制返回属性
                //searchCtls.setReturningAttributes(returnedAtts); // 设置返回属性集
                NamingEnumeration list = ctx.search(searchBase, null, searchCtls);// Search for objects using the filter
                int totalResults = 0;// Specify the attributes to return
                int rows = 0;
                while (list.hasMoreElements()) {// 遍历结果集
                    String uName = "";
                    SearchResult sr = (SearchResult) list.next();// 得到符合搜索条件的DN
                    String dn = sr.getName();
                    System.out.println("dn------------------" + dn);
                    // System.out.println(dn);
                    String match = dn.split("CN=")[1].split(",")[0];//返回格式一般是CN=ptyh,OU=专卖

                    Attributes Attrs = sr.getAttributes();// 得到符合条件的属性集
                    //System.out.println(Attrs.size());
                    if (Attrs != null) {
                        try {
                            for (NamingEnumeration ne = Attrs.getAll(); ne.hasMore(); ) {

                                Attribute Attr = (Attribute) ne.next();// 得到下一个属性'
                                System.out.println(" AttributeID=属性名："+ Attr.getID().toString());
                                // 读取属性值
                                for (NamingEnumeration e = Attr.getAll(); e.hasMore(); totalResults++) {
                                    String company = e.next().toString();
                                    System.out.println("  AttributeValues=属性值：" + company);
                                }
                            }
                        } catch (NamingException e) {
                            System.err.println("Throw Exception : " + e);
                        }
                    }

                }
            }
        }catch (NamingException e) {
            e.printStackTrace();
            return;
        }

        try {
            if(ctx != null)
                ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }

        Iterator<Map.Entry<String,String>> it = map.entrySet().iterator();
        while(it.hasNext()){
            Map.Entry<String,String> entry = it.next();
            System.out.println("Key:"+entry.getKey());
            System.out.println("Value:"+entry.getValue());
        }
    }

    public static void main(String[] args) {
        readLdap("vdmptest2");
    }

}
