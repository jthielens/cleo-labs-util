package com.cleo.labs.util;

import static org.junit.Assert.*;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XMLTest {
    private static final Pattern KEY_INDEX = Pattern.compile("(\\w+)(?:\\[(.+)\\]|\\.(.+))?");
    // word (alone), or word[index] (group(2) is index), or word.index (group(3) is index)
    @SuppressWarnings("unchecked")
    public static Document map2xml(Map<String,Object> map) throws ParserConfigurationException {
        Document doc = DocumentBuilderFactory.newInstance()
                                             .newDocumentBuilder()
                                             .newDocument();
        Element elem = null;
        Deque<Iterator<Entry<String,Object>>> qi = new ArrayDeque<Iterator<Entry<String,Object>>>();
        Deque<Element>                        qe = new ArrayDeque<Element>();
        Iterator<Entry<String,Object>> i = map.entrySet().iterator();
        while (i.hasNext()) {
            Entry<String,Object> e = i.next();
            String key = e.getKey();
            if (e.getValue() instanceof String) {
                if (key.startsWith(".")) {
                    elem.setAttribute(key.substring(1), (String)e.getValue());
                } else {
                    Matcher m = KEY_INDEX.matcher(key);
                    m.matches();
                    key = m.group(1);
                    String index = m.group(2)!=null ? m.group(2) : m.group(3);
                    String text = (String)e.getValue();
                    if (index!=null) {
                        // Advanced.key          = value --> Advanced        key=value
                        // Other.key             = value --> Other           key=value
                        // Contenttypedirs[type] = value --> Contenttypedirs type=value
                        // Syntax|Header[verb]   = value --> Syntax|Header   verb value
                        if (key.equalsIgnoreCase("Advanced") ||
                            key.equalsIgnoreCase("Contenttypedirs") ||
                            key.equalsIgnoreCase("Other")) {
                            text = index + "=" + text;
                        } else if (key.equalsIgnoreCase("Syntax") || key.equalsIgnoreCase("Header")) {
                            if (text.isEmpty()) {
                                text = index;
                            } else {
                                text = index + " " + text;
                            }
                        }
                    }
                    Element param = doc.createElement(key);
                    param.appendChild(doc.createTextNode(text));
                    elem.appendChild(param);
                }
            } else {
                key = key.split("\\[", 2)[0];  // split off key[index] to just key
                Element newelem = doc.createElement(key);
                if (elem==null) {
                    doc.appendChild(newelem);
                    elem = newelem;
                } else {
                    elem.appendChild(newelem);
                }
                qi.push(i);
                qe.push(elem);
                i = ((Map<String,Object>)e.getValue()).entrySet().iterator();
                elem = newelem;
            }
            while (!i.hasNext() && !qi.isEmpty()) {
                i = qi.pop();
                elem = qe.pop();
            }
        }
        return doc;
    }

    @Test
    public void testWrite() throws Exception {
        LDAP ldap = new LDAP("ldap(apache,starttls,default,user=cn,uid=cn,mail=mail,name=displayName)://alice:cleo@192.168.50.120:389 2/ou=people,dc=cleo,dc=demo?(objectClass=inetOrgPerson)");
        Map<String,Object> map = ldap.toMap();
        String out = X.xml2string(map2xml(Collections.singletonMap("Options", Collections.singletonMap("Ldapserver", map))));
        assertTrue(out.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n<Options>"));
    }

}
