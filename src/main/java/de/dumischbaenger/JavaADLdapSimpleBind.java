package de.dumischbaenger;

import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.security.Principal;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.dumischbaenger.tools.Role;
import de.dumischbaenger.tools.RoleFetcherSimpleBind;

public class JavaADLdapSimpleBind {
  static private Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  public static void main(String[] args) {

    LOG.info("program started");

    try {
      // load a properties file from class path, inside static method
      InputStream is = JavaADLdapSimpleBind.class.getResourceAsStream("/config.properties");
      System.getProperties().load(is);
    } catch (IOException ex) {
      ex.printStackTrace();
      LOG.info("cannot read config file",ex);
      System.exit(1);

    }

    String props[] = {
        "ldapBindDn",
        "ldapPassword",
        "ldapURL",
        "ldapKeystore",
        "ldapSearchBase",
        "ldapFilter",
        "ldapReturnAttr",
        "ldapKeystorePWD"
    };

    for (int i = 0; i < props.length; i++) {
      LOG.info(props[i] + ": " + System.getProperty(props[i]));
    }

    
    Set<Principal> principals=new HashSet<>();
    addRoleToSubject(principals);
    printPrincipals(principals);

    LOG.info("program stopped");
  }

  private static void printPrincipals(Set<Principal> myPrincipalsSet) {
     Principal principal;
     Iterator<Principal> myIt = myPrincipalsSet.iterator();
     while (myIt.hasNext()) {
     principal = (Principal) myIt.next();
     LOG.info(
     "principal classname: "
     + principal.getClass().getName()
     + " - value: "
     + principal.getName());
     }
    
  }

  private static void addRoleToSubject(Set<Principal> principals) {
    RoleFetcherSimpleBind roleFetcherSimpleBind = new RoleFetcherSimpleBind();
    roleFetcherSimpleBind.fetchRoles();

    if (roleFetcherSimpleBind.getRoleAsEnumeration() != null) {
      String fullRoleName;
      String roleName;
      while (roleFetcherSimpleBind.getRoleAsEnumeration().hasMoreElements()) {
        fullRoleName = roleFetcherSimpleBind.getRoleAsEnumeration().nextElement().toString();

        if (fullRoleName.indexOf("CN") != -1) {
          roleName = fullRoleName.substring(fullRoleName.indexOf("CN") + 3, fullRoleName.indexOf(","));
           Role jrp = new Role(roleName);
           principals.add(jrp);
        }

      }
    } else {
      LOG.info("user has no roles");
    }
  }

}
