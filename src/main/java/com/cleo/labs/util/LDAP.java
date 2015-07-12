package com.cleo.labs.util;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class LDAP {

    public enum Type {
        AD     ("Active Directory"),
        APACHE ("Apache Directory Services"),
        DOMINO ("Lotus Domino (IBM)"),
        NOVELL ("Novell eDirectory"),
        DIRX   ("DirX (Siemens)");

        public final String tag;
        private Type (String tag) {
            this.tag = tag;
        }

        private static final Map<String,Type> index = new HashMap<String,Type>();
        static { for (Type t : Type.values()) index.put(t.tag.toLowerCase(), t); }
        public static Type lookup(String name) { return index.get(name.toLowerCase()); }
    }

    public enum Option {
        DISABLED, // if config is present but enabled=False
        STARTTLS, // affects security mode
        DEFAULT,  // Maintain Default LDAP User Group
        SRV,      // Lookup SRV records from DNS
        CHECKPW,  // Check AD password expiration
        WARNUSER, // Email user with AD password expiration warnings
        VLNAV;    // VLNavigator uses enabled attribute instead of Enabled element
    }

    public enum SecurityMode {
        NONE     ("None"),
        SSL      ("SSL"),
        STARTTLS ("StartTLS");
        
        public String tag;
        private SecurityMode(String tag) {
            this.tag = tag;
        }

        private static final Map<String,SecurityMode> index = new HashMap<String,SecurityMode>();
        static { for (SecurityMode s : SecurityMode.values()) index.put(s.tag.toLowerCase(), s); }
        public static SecurityMode lookup(String name) { return index.get(name.toLowerCase()); }
    }

    private static final String SRVRECORDS = "Srvrecords";

    public enum Attr {
        // these are for mapping LDAP attributes
        USER    ("Attribute"),
        MAIL    ("Emailaddressattribute"),
        HOME    ("Homedirattribute"),
        NAME    ("Fullnameattribute"),
        FIRST   ("Firstnameattribute"),
        LAST    ("Lastnameattribute"),
        PASS    (null, "userPassword", false, true),
        // these are for AD password checking
        DAYS    ("Warningdays",    "7"),
        TIME    ("Checktimeidx",   "0"), // # of 30 minute ticks since midnight :-(
        TO      ("Emailrecipient", "%admin%"),
        FROM    ("Emailsender",    "%admin%"),
        SUBJECT ("Subject",        "Cleo Communications US, LLC Password Expiration Notice"),
        // these are indirect ones
        MODE     ("Security",            SecurityMode.NONE.tag, true),
        TYPE     ("Type",                Type.APACHE.tag,       true),
        DEFAULT  ("Defaultldapug",       "",                    true),
        CHECKPW  ("Pwdcheckingenabled",  "False",               true),
        LOOKUP   ("Lookupenabled",       "False",               true),
        WARNUSER ("Emailusers",          "False",               true),
        VENABLED (".enabled",            "",                    true),
        OENABLED ("Enabled",             "",                    true),
        SRV      ("Lookupenabled",       "False",               true),
        DNS      ("Dnsdomain",           "",                    true),
        HOST     (SRVRECORDS+"/Host",    "",                    true),
        PORT     (SRVRECORDS+"/Port",    "389",                 true),
        PRIORITY (SRVRECORDS+"/Priority","1",                   true),
        WEIGHT   (SRVRECORDS+"/Weight",  "1",                   true),
        TTL      (SRVRECORDS+"/Ttl",     "86400",               true),
        FAILED   (SRVRECORDS+"/Failed",  "False",               true),
        VSENABLED(SRVRECORDS+"/.enabled","",                    true),
        OSENABLED(SRVRECORDS+"/Enabled", "",                    true),
        USERNAME ("Ldapusername",        "",                    true),
        PASSWORD ("Ldappassword",        "",                    true),
        BASEDN   ("Ldapdomain",          "",                    true),
        DOMAIN   ("Domain",              "",                    true), // dupe of BASEDN
        FILTER   ("Filter",              "",                    true);

        public final String  tag;
        public final String  dflt;
        public final boolean indirect;
        public final boolean mapped;
        
        private Attr (String tag) {
            this.tag      = tag;
            this.dflt     = "";
            this.indirect = false;
            this.mapped   = true;
        }
        private Attr (String tag, String dflt) {
            this.tag      = tag;
            this.dflt     = dflt;
            this.indirect = false;
            this.mapped   = false;
        }
        private Attr (String tag, String dflt, boolean indirect) {
            this.tag      = tag;
            this.dflt     = dflt;
            this.indirect = indirect;
            this.mapped   = false;
        }
        private Attr (String tag, String dflt, boolean indirect, boolean mapped) {
            this.tag      = tag;
            this.dflt     = dflt;
            this.indirect = indirect;
            this.mapped   = mapped;
        }

        private static final Map<String,Attr> index = new HashMap<String,Attr>();
        static { for (Attr a : Attr.values()) if (a.tag!=null) index.put(a.tag.toLowerCase(), a); }
        public static Attr lookup(String name) { return index.get(name.toLowerCase()); }
    }

    public interface Crypt {
        public String encrypt(String s) throws Exception;
        public String decrypt(String s) throws Exception;
    }

    public static class NoCrypt implements Crypt {
        public String encrypt(String s) { return s; }
        public String decrypt(String s) { return s; }
    }
    public static final NoCrypt nocrypt = new NoCrypt();

    private SecurityMode getMode()            { return SecurityMode.lookup(attrs.get(Attr.MODE)); }

    private String       getAttr(EnumMap<Attr,String> map, Attr a) { String v = map.get(a); return v==null ? "" : v; }
    private boolean      getBool(EnumMap<Attr,String> map, Attr a) { return getAttr(map, a).equalsIgnoreCase(Boolean.toString(true)); }
    private void         setBool(EnumMap<Attr,String> map, Attr a, boolean b) { map.put(a, b?"True":"False"); }
    private boolean      isDefault(EnumMap<Attr,String> map, Attr a) { return getAttr(map, a).equals(a.dflt); }
    private void         setIf  (EnumMap<Attr,String> map, Attr a, String s)  { if (s!=null && !s.isEmpty()) map.put(a,  s); }

    private String       getAttr(Attr a) { return getAttr(attrs, a); }
    private boolean      getBool(Attr a) { return getBool(attrs, a); }
    private void         setBool(Attr a, boolean b) { setBool(attrs, a, b); }
    private void         setIf  (Attr a, String s)  { setIf(attrs, a, s); }

    /*------------------------*
     * LDAP Server Definition *
     *------------------------*/
    private EnumMap<Attr,String>       attrs = new EnumMap<>(Attr.class);
    private List<EnumMap<Attr,String>> srvs  = new ArrayList<>();

    public LDAP () {
        // set up defaults
        for (Attr attr : Attr.values()) {
            if (attr.dflt!=null && !attr.dflt.isEmpty()) {
                this.attrs.put(attr, attr.dflt);
            }
        }
    }

    // ldap[s][(type|opt|map...)]://[user:pass@]host[:port priority weight ttl]/basedn[?filter]
    // type = ad|apache|domino|novell|dirx
    // opt  = starttls|default
    // map  = (user|mail|name|home|first|last)=attr
    static final Pattern LDAP_PATTERN = Pattern.compile("ldap(s)?(?:\\((.*)\\))?://(?:(.*?):(.*)@)?([^:]*(?::[\\d ]+)?(?:,[^:]*(?::[\\d ]+)?)*)/(.*?)(?:\\?(.*))?");
    public LDAP (String s) {
        // set up defaults
        this();
        // parse string
        Matcher m = LDAP_PATTERN.matcher(s);
        if (m.matches()) {
            String ssl      = m.group(1);
            String opts     = m.group(2);
            String user     = m.group(3);
            String password = m.group(4);
            String hosts    = m.group(5);
            String basedn   = m.group(6);
            String filter   = m.group(7);
            // process opts into options and attributes
            EnumSet<Option> options = EnumSet.noneOf(Option.class);
            if (opts!=null && !opts.isEmpty()) {
                for (String opt : opts.split("\\s*,\\s*")) {
                    String[] kv = opt.split("\\s*=\\s*", 2);
                    if (kv.length==2) {
                        // attribute=value: look it up
                        Attr attr;
                        try {
                            attr = Attr.valueOf(kv[0].toUpperCase());
                        } catch (IllegalArgumentException e) {
                            throw new IllegalArgumentException("unrecognized attribute: "+kv[0]);
                        }
                        if (attr.indirect) {
                            throw new IllegalArgumentException("unrecognized attribute: "+kv[0]);
                        }
                        this.attrs.put(Attr.valueOf(kv[0].toUpperCase()), kv[1]);
                    } else if (!opt.isEmpty()) {
                        // option: look it up as an Option or a Type
                        try {
                            options.add(Option.valueOf(opt.toUpperCase()));
                        } catch (IllegalArgumentException e) {
                            try {
                                this.attrs.put(Attr.TYPE, Type.valueOf(opt.toUpperCase()).tag);
                            } catch (IllegalArgumentException f) {
                                throw new IllegalArgumentException("unrecognized option: "+opt);
                            }
                        }
                    }
                }
            }
            // parse port priority weight ttl
            for (String host : hosts.split(",")) {
                if (!host.isEmpty()) {
                    String[] hp     = host.split(":", 2);
                    host            = hp[0];
                    String   port   = hp.length>1 ? hp[1] : null;
                    String[] ppwt   = port==null ? new String[0] : port.split(" ");
                    String priority = ppwt.length>1 && !ppwt[1].isEmpty() ? ppwt[1] : null;
                    String weight   = ppwt.length>2 && !ppwt[2].isEmpty() ? ppwt[2] : null;
                    String ttl      = ppwt.length>3 && !ppwt[3].isEmpty() ? ppwt[3] : null;
                    port            = ppwt.length>0 && !ppwt[0].isEmpty() ? ppwt[0] : null;
                    EnumMap<Attr,String> srv = new EnumMap<>(Attr.class);
                    setIf(srv, Attr.HOST,     host);
                    setIf(srv, Attr.PORT,     port);
                    setIf(srv, Attr.PRIORITY, priority);
                    setIf(srv, Attr.WEIGHT,   weight);
                    setIf(srv, Attr.TTL,      ttl);
                    if (options.contains(Option.VLNAV)) {
                        setBool(srv, Attr.VSENABLED, true);
                    } else {
                        setBool(srv, Attr.OSENABLED, true);
                    }
                    srvs.add(srv);
                }
            }
            // set simple ones
            setIf(Attr.USERNAME, user);
            setIf(Attr.PASSWORD, password);
            setIf(Attr.BASEDN,   basedn);
            setIf(Attr.DOMAIN,   basedn); // dupe of basedn
            setIf(Attr.FILTER,   filter);
            // figure out if this should be disabled
            if (options.contains(Option.VLNAV)) {
                setBool(Attr.VENABLED, !options.contains(Option.DISABLED));
            } else {
                setBool(Attr.OENABLED, !options.contains(Option.DISABLED));
            }
            // figure out if mode should be set differently from default
            if (options.contains(Option.STARTTLS)) {
                this.attrs.put(Attr.MODE, SecurityMode.STARTTLS.tag);
            } else if (ssl!=null) {
                this.attrs.put(Attr.MODE, SecurityMode.SSL.tag);
            }
            // hosts means something different with SRV
            if (options.contains(Option.SRV)) {
                srvs = new ArrayList<>();
                this.attrs.put(Attr.DNS, hosts);
            }
            // DEFAULT applies only for VLNav
            if (options.contains(Option.VLNAV)) {
                setBool(Attr.DEFAULT,  options.contains(Option.DEFAULT));
            }
            // remaining straight up options
            setBool(Attr.CHECKPW,  options.contains(Option.CHECKPW));
            setBool(Attr.WARNUSER, options.contains(Option.WARNUSER));
            setBool(Attr.SRV,      options.contains(Option.SRV));
        } else {
            throw new IllegalArgumentException("can not parse LDAP string: "+s);
        }
    }

    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append("ldap");
        if (getMode()==SecurityMode.SSL) s.append('s');
        boolean vlnav = attrs.containsKey(Attr.VENABLED);
        boolean disabled = !getBool(vlnav ? Attr.VENABLED : Attr.OENABLED);
        ArrayList<String> list = new ArrayList<String>();
        if (disabled                   ) list.add(Option.DISABLED.name().toLowerCase());
        list.add(Type.lookup(getAttr(Attr.TYPE)).name().toLowerCase());
        if (getMode()==SecurityMode.STARTTLS) list.add(Option.STARTTLS.name().toLowerCase());
        if (getBool(Attr.DEFAULT)      ) list.add(Option.DEFAULT.name().toLowerCase());
        if (getBool(Attr.CHECKPW)      ) list.add(Option.CHECKPW.name().toLowerCase());
        if (getBool(Attr.WARNUSER)     ) list.add(Option.WARNUSER.name().toLowerCase());
        if (vlnav                      ) list.add(Option.VLNAV.name().toLowerCase());
        for (Map.Entry<Attr,String> e : attrs.entrySet()) {
            if (!e.getKey().indirect && !e.getValue().equals(e.getKey().dflt)) {
                list.add(e.getKey().name().toLowerCase()+"="+e.getValue());
            }
        }
        if (!list.isEmpty()) {
            s.append('(')
             .append(S.join(",", list))
             .append(')');
        }
        s.append("://");
        if (!getAttr(Attr.USERNAME).isEmpty() || !getAttr(Attr.PASSWORD).isEmpty()) {
            s.append(getAttr(Attr.USERNAME));
            if (!getAttr(Attr.PASSWORD).isEmpty()) s.append(':').append(getAttr(Attr.PASSWORD));
            s.append('@');
        }
        if (getBool(Attr.SRV)) {
            s.append(':').append(getAttr(Attr.DNS));
        } else {
            boolean first = true;
            for (EnumMap<Attr,String> srv : srvs) {
                if (!first) s.append(',');
                first = false;
                s.append(srv.get(Attr.HOST));
                if (isDefault(srv, Attr.PRIORITY) && isDefault(srv, Attr.WEIGHT) && isDefault(srv, Attr.TTL)) {
                    if (!isDefault(srv, Attr.PORT)) {
                        s.append(':').append(srv.get(Attr.PORT));
                    }
                } else {
                    s.append(':').append(srv.get(Attr.PORT))
                     .append(' ').append(srv.get(Attr.PRIORITY))
                     .append(' ').append(srv.get(Attr.WEIGHT))
                     .append(' ').append(srv.get(Attr.TTL));
                }
            }
        }
        s.append('/');
        s.append(getAttr(Attr.BASEDN));
        if (!getAttr(Attr.FILTER).isEmpty()) s.append('?').append(getAttr(Attr.FILTER));
        return s.toString();
    }

    public Map<String,Object> toMap() throws Exception {
        return toMap(nocrypt);
    }
    public Map<String,Object> toMap(Crypt crypt) throws Exception {
        Map<String,Object> map = new TreeMap<String,Object>();
        for (Attr a : Attr.values()) {
            if (a.tag!=null && !a.tag.startsWith(SRVRECORDS)) {
                String value;
                if (attrs.containsKey(a)) {
                    value = attrs.get(a);
                    if (a==Attr.PASSWORD) {
                        value = crypt.encrypt(value);
                    }
                } else {
                    value = a.dflt;
                }
                if (value!=null && !value.isEmpty()) {
                    map.put(a.tag, value);
                }
            }
        }
        for (int i=0; i<srvs.size(); i++) {
            EnumMap<Attr,String> srv = srvs.get(i);
            Map<String,Object> srvmap = new TreeMap<String,Object>();
            for (Attr a : Attr.values()) {
                if (a.tag!=null && a.tag.startsWith(SRVRECORDS)) {
                    String value = srv.containsKey(a) ? srv.get(a) : a.dflt;
                    if (value!=null && !value.isEmpty()) {
                        srvmap.put(a.tag.substring(SRVRECORDS.length()+1), value);
                    }
                }
            }
            map.put(SRVRECORDS+"["+i+"]", srvmap);
        }
        return map;
    }

    public LDAP (Map<String,Object> map) throws Exception {
        this(map, nocrypt);
    }
    public LDAP (Map<String,Object> map, Crypt crypt) throws Exception {
        // set up defaults
        this();
        // walk the map
        for (Map.Entry<String,Object> e : map.entrySet()) {
            if (e.getKey().startsWith(SRVRECORDS)) {
                try {
                    @SuppressWarnings("unchecked")
					Map<String, Object> srvmap = (Map<String,Object>)e.getValue();
                    EnumMap<Attr,String> srv = new EnumMap<>(Attr.class);
                    for (Map.Entry<String,Object> s : srvmap.entrySet()) {
                        String key = SRVRECORDS+"/"+s.getKey();
                        Attr a = Attr.lookup(key);
                        if (a==null) {
                            throw new IllegalArgumentException("unrecognized attribute: "+key);
                        } else if (!(s.getValue() instanceof String)) {
                            throw new IllegalArgumentException("String value expected for attribute: "+key);
                        }
                        srv.put(a, (String)s.getValue());
                    }
                    srvs.add(srv);
                } catch (ClassCastException cce) {
                    throw new IllegalArgumentException("Nested object expected for attribute: "+e.getKey());
                }
            } else {
                Attr a = Attr.lookup(e.getKey());
                if (a==null) {
                    throw new IllegalArgumentException("unrecognized attribute: "+e.getKey());
                }
                if (!(e.getValue() instanceof String)) {
                    throw new IllegalArgumentException("String value expected for attribute: "+e.getKey());
                }
                String value = (String)e.getValue();
                if (a==Attr.PASSWORD) {
                    value = crypt.decrypt(value);
                }
                attrs.put(a, value);
            }
        }
    }

    public String[] attributes() {
        ArrayList<String> list = new ArrayList<String>();
        for (Attr a : Attr.values()) {
            if (a.mapped) {
                if (!getAttr(a).isEmpty()) {
                    list.add(attrs.get(a));
                }
            }
        }
        return list.toArray(new String[list.size()]);
    }

    private DirContext getContext(String admin, String password) throws NamingException {
        Hashtable<String,Object> env = new Hashtable<String,Object>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        if (admin!=null) {
            env.put(Context.SECURITY_PRINCIPAL, admin);
        } else if (attrs.containsKey(Attr.USERNAME)) {
            env.put(Context.SECURITY_PRINCIPAL, getAttr(Attr.USER)+"="+
                                                getAttr(Attr.USERNAME)+","+
                                                getAttr(Attr.BASEDN));
        }
        if (password!=null) {
            env.put(Context.SECURITY_CREDENTIALS, password);
        } else if (attrs.containsKey(Attr.PASSWORD)) {
            env.put(Context.SECURITY_CREDENTIALS, getAttr(Attr.PASSWORD));
        }
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://"+srvs.get(0).get(Attr.HOST)+
                                      ":"+srvs.get(0).get(Attr.PORT));
        return new InitialDirContext(env);
    }

    /**
     * Searches the LDAP directory for an entry matching {@code Attribute.USER} against
     * the requested {@code alias}.  All connection parameters are derived from the {@code Attributes}
     * set in the {@code attrs} member.  Returns a Map indexed by {@code Attribute} containing the
     * associated values, i.e. the Map maps Attribute.USER => 'alice', not 'cn' => 'alice'.
     * <p>
     * If an entry is not found, the returned Map is empty.  If there is an LDAP problem, an
     * Exception is thrown
     * @param alias the alias to search for
     * @return the attributes of the entry found, organized by {@Attribute}
     * @throws Exception
     */
    public Map<Attr,String> find(String alias) throws Exception {
        DirContext ctx = getContext(null, null);
        Map<Attr,String> entry = new TreeMap<Attr,String>();
        String base = getAttr(Attr.BASEDN);

        SearchControls sc = new SearchControls();
        sc.setReturningAttributes(attributes());
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String filter = "("+getAttr(Attr.USER)+"="+alias+")";
        if (attrs.containsKey(Attr.FILTER) && !getAttr(Attr.FILTER).isEmpty()) {
            filter = "(&"+filter+getAttr(Attr.FILTER)+")";
        }

        NamingEnumeration<SearchResult> results = ctx.search(base, filter, sc);
        if (results.hasMore()) {
          SearchResult sr = results.next();
          Attributes found = sr.getAttributes();
          for (Attr a : Attr.values()) {
              if (a.mapped) {
                  String mapped = getAttr(a);
                  if (mapped!=null && !mapped.isEmpty()) {
                      if (found.get(mapped)!=null) {
                          entry.put(a, found.get(mapped).get().toString());
                      }
                  }
              }
          }
        }
        ctx.close();
        return entry;
    }

    public void add(Map<Attr,String> entry) throws Exception {
        add(null, null, entry);
    }
    public void add(String admin, String password, Map<Attr,String> entry) throws Exception {
        DirContext ctx = getContext(admin, password);
        Attributes attributes=new BasicAttributes();
        attributes.put(new BasicAttribute("objectClass", "inetOrgPerson"));
        attributes.put(new BasicAttribute("uid", entry.get(Attr.USER)));

        for (Map.Entry<Attr,String> e : entry.entrySet()) {
            Attr a = e.getKey();
            if (a.mapped) {
                String value = e.getValue();
                if (a==Attr.PASS) {
                    value = SSHA.hash(value);
                }
                attributes.put(new BasicAttribute(getAttr(a), value));
            }
            
        }
        // compute the dn and update
        String dn = "cn="+entry.get(Attr.USER)+","+getAttr(Attr.BASEDN);
        ctx.createSubcontext(dn, attributes);
    }
}