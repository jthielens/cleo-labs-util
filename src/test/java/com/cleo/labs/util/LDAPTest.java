package com.cleo.labs.util;

import static org.junit.Assert.*;

import org.junit.Test;

public class LDAPTest {

    @Test
    public void test() throws Exception {
        LDAP ldap = new LDAP("ldap(apache,starttls,default,user=cn,uid=cn,mail=mail,name=displayName)://alice:cleo@192.168.50.120:389 2/ou=people,dc=cleo,dc=demo?(objectClass=inetOrgPerson)");
        System.out.println(X.map2tree(ldap.toMap()));
        assertEquals(ldap.toMap().get("Domain"), "ou=people,dc=cleo,dc=demo");
    }

    @Test
    public void test2() throws Exception {
        LDAP ldap = new LDAP("ldap(vlnav,apache,starttls,default,user=cn,mail=mail,name=test2)://alice:cleo@192.168.50.120:389 2/ou=people,dc=cleo,dc=demo?(objectClass=inetOrgPerson)");
        System.out.println(X.map2tree(ldap.toMap()));
        assertEquals(ldap.toMap().get("Domain"), "ou=people,dc=cleo,dc=demo");
    }

    @Test
    public void testSrv() throws Exception {
        LDAP ldap = new LDAP("ldap(srv,vlnav)://user:pass@cleo.com/ou=people,dc=cleo,dc=demo?(objectClass=inetOrgPerson)");
        System.out.println(X.map2tree(ldap.toMap()));
        assertEquals(ldap.toMap().get("Dnsdomain"), "cleo.com");
    }

    @Test
    public void testSample() throws Exception {
        LDAP ldap = new LDAP("ldap(apache,user=cn,mail=mail,name=displayName)://alice:vlenc:fa64a500-a6a0-4724-82ad-7797957ada35:77239e72670dbec3ab483aa74ea2c8b5@192.168.50.120:389 2 2 300,192.168.50.120:390 10 10 86400/ou=people,dc=cleo,dc=demo");
        System.out.println(X.map2tree(ldap.toMap()));
        assertEquals(ldap.toMap().get("Domain"), "ou=people,dc=cleo,dc=demo");
    }

    @Test
    public void testNothin() throws Exception {
        LDAP ldap = new LDAP("ldap(disabled,apache,vlnav,subject=Password Expiration Notice):///");
        System.out.println(X.map2tree(ldap.toMap()));
        assertEquals("False", ldap.toMap().get(".enabled"));
    }
}
