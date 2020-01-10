package com.vzt.vdmp.controller;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.Hashtable;

public class AddDemon {
    /**
     * 使用java连接AD域
     * @return void
     * @throws
     * @param username 用户名
     * @param password 密码
     */
    private  void connect(String username,String password) {
        DirContext ctx=null;
        String company = "";
        Hashtable<String,String> HashEnv = new Hashtable<String,String>();
        HashEnv.put(Context.SECURITY_AUTHENTICATION, "simple"); // LDAP访问安全级别(none,simple,strong)
        HashEnv.put(Context.SECURITY_PRINCIPAL, username); //AD的用户名
        HashEnv.put(Context.SECURITY_CREDENTIALS, password); //AD的密码
        HashEnv.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory"); // LDAP工厂类
        HashEnv.put("com.sun.jndi.ldap.connect.timeout", "3000");//连接超时设置为3秒
        HashEnv.put(Context.PROVIDER_URL, "ldaps://ch2windc03p.htichina.net:636/");// 默认端口389
        try {
            ctx = new InitialDirContext(HashEnv);// 初始化上下文
            System.out.println("身份验证成功!");
            // 域节点
            String searchBase = "CN=Users,DC=htichina,DC=net";
            String baseDn = "CN=VDMP,CN=Users,DC=htichina,DC=net";
            // LDAP搜索过滤器类

            String searchFilter = "(&(objectCategory= CN=Person,CN=Schema,CN=Configuration,DC=htichina,DC=net)(objectClass=user)(memberof="+baseDn+")(sAMAccountName=" + username + "))";             // 搜索控制器
            SearchControls searchCtls = new SearchControls(); // Create the
            // 创建搜索控制器
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE); // Specify
            // 设置搜索范围
            // searchCtls.setSearchScope(SearchControls.OBJECT_SCOPE); //
            // Specify the search scope 设置搜索范围
            //String returnedAtts[] = { "memberOf", "distinguishedName",
            //"Pwd-Last-Set", "User-Password", "cn" };// 定制返回属性
            //String returnedAtts[] = { "sAMAccountName","cloudExtensionAttribute" };// 定制返回属性

            // String returnedAtts[] = { "url", "whenChanged", "employeeID",
            // "name", "userPrincipalName", "physicalDeliveryOfficeName",
            // "departmentNumber", "telephoneNumber", "homePhone",
            // "mobile", "department", "sAMAccountName", "whenChanged",
            // "mail" }; // 定制返回属性
            //searchCtls.setReturningAttributes(returnedAtts); // 设置返回属性集
            // 根据设置的域节点、过滤器类和搜索控制器搜索LDAP得到结果
            NamingEnumeration answer = ctx.search(searchBase, searchFilter, searchCtls);// Search for objects using the filter
            // 初始化搜索结果数为0
            int totalResults = 0;// Specify the attributes to return
            int rows = 0;
            while (answer.hasMoreElements()) {// 遍历结果集
                String uName= "";
                SearchResult sr = (SearchResult) answer.next();// 得到符合搜索条件的DN
                String dn = sr.getName();
                System.out.println("dn------------------"+dn);
                // System.out.println(dn);
                String match = dn.split("CN=")[1].split(",")[0];//返回格式一般是CN=ptyh,OU=专卖

                Attributes Attrs = sr.getAttributes();// 得到符合条件的属性集
                //System.out.println(Attrs.size());
                if (Attrs != null) {
                    try {
                        for (NamingEnumeration ne = Attrs.getAll(); ne.hasMore();) {

                            Attribute Attr = (Attribute) ne.next();// 得到下一个属性'
                            //System.out.println(" AttributeID=属性名："+ Attr.getID().toString());
                            // 读取属性值
                            for (NamingEnumeration e = Attr.getAll(); e.hasMore(); totalResults++) {
                                company = e.next().toString();
                                if(company.equals("vdmptest2")) {
                                    System.out.println("  AttributeValues=属性值：" + company);
                                }
                            }
                        }
                    } catch (NamingException e) {
                        System.err.println("Throw Exception : " + e);
                    }
                }



                System.out.println("************************************************");
                System.out.println("Number: " + totalResults);
                ctx.close();
            }
        } catch (AuthenticationException e) {
            System.out.println("身份验证失败!");
            e.printStackTrace();
        } catch (javax.naming.CommunicationException e) {
            System.out.println("AD域连接失败!");
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println("身份验证未知异常!");
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
    }

    public static void main(String[] args) {
        AddDemon demo = new AddDemon();
        demo.connect("CN=IAMDomainAdmin,OU=Service Accounts,OU=Service_Group,OU=Internal,OU=China,DC=htichina,DC=net", "T-systemsT-systems");
    }


}
