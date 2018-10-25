package de.dumischbaenger.tools;
import java.lang.invoke.MethodHandles;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class RoleFetcherSimpleBind {
  static private Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());


  private NamingEnumeration<?> role = null;

  public void fetchRoles() {
  
    String ldapBindDn = System.getProperty("ldapBindDn");
    String ldapPassword = System.getProperty("ldapPassword");
    String ldapURL =  System.getProperty("ldapURL");
    String ldapSearchBase =  System.getProperty("ldapSearchBase");
    String ldapFilter =  System.getProperty("ldapFilter");
    String ldapReturnAttr =  System.getProperty("ldapReturnAttr");
  
    
    Hashtable<String,Object> env = new Hashtable<String, Object>(11);
    env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL,ldapURL);
    
  
    env.put(Context.SECURITY_AUTHENTICATION, "simple");
    env.put(Context.SECURITY_PRINCIPAL, ldapBindDn);
    env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
    
    // Specify SSL
    //env.put(Context.SECURITY_PROTOCOL, "ssl");

    
    //turn on ldap trace
    //env.put("com.sun.jndi.ldap.trace.ber", System.err);

  
    try {
  
      DirContext ctx = new InitialDirContext(env);
      
      SearchControls ctrls = new SearchControls();
      ctrls.setReturningAttributes(ldapReturnAttr.split(","));
      ctrls.setSearchScope(SearchControls.SUBTREE_SCOPE);

      NamingEnumeration<SearchResult> answers = ctx.search(ldapSearchBase, ldapFilter, ctrls);
      
      
      while (answers.hasMoreElements()) {
        SearchResult sr = (SearchResult) answers.next();
        Attributes userAttributes = sr.getAttributes();
        
        NamingEnumeration<String> ids=userAttributes.getIDs();
        while(ids.hasMoreElements()) {
          String id=ids.next();
          LOG.info("AttributName="+id + " AttributValue="+userAttributes.get(id));
          
        }
        Attribute at = userAttributes.get("memberOf");
  
        if (at != null) {
          role = at.getAll();
        } else {
          role = null;
        }
  
      }
    } catch (NamingException e) {
      e.printStackTrace();
      role = null;
  
    }
  }
  public NamingEnumeration<?> getRoleAsEnumeration() {

    return role;

  }

}
