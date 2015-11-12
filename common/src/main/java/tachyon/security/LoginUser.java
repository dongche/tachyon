/*
 * Licensed to the University of California, Berkeley under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package tachyon.security;

import java.io.IOException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import tachyon.Constants;
import tachyon.conf.TachyonConf;
import tachyon.security.authentication.AuthType;
import tachyon.security.login.TachyonJaasConfiguration;

/**
 * A Singleton of LoginUser, which is an instance of {@link tachyon.security.User}. It represents
 * the user of Tachyon client, when connecting to Tachyon service.
 *
 * The implementation of getting a login user supports Windows, Unix, and Kerberos login modules.
 *
 * This singleton uses lazy initialization.
 */
public final class LoginUser {

  /** User instance of the login user in Tachyon client process */
  private static User sLoginUser;

  private LoginUser() {} // prevent instantiation

  /**
   * Gets current singleton login user. This method is called to identify the singleton user who
   * runs Tachyon client. When Tachyon client gets a user by this method and connects to Tachyon
   * service, this user represents the client and is maintained in service.
   *
   * @param conf Tachyon configuration
   * @return the login user
   * @throws java.io.IOException if login fails
   */
  public static User get(TachyonConf conf) throws IOException {
    if (sLoginUser == null) {
      synchronized (LoginUser.class) {
        if (sLoginUser == null) {
          sLoginUser = getLoginUser(conf);
        }
      }
    }
    return sLoginUser;
  }

  private static User getLoginUser(TachyonConf conf) throws IOException {
    AccessControlContext context = AccessController.getContext();
    Subject subject = Subject.getSubject(context);

    // login, if no proper subject in context
    if (subject == null || subject.getPrincipals(User.class).isEmpty()) {
      return login(conf, null);
    }

    // fetch user from subject in context, if any
    Set<User> userSet = subject.getPrincipals(User.class);
    if (userSet.size() > 1) {
      throw new IOException("More than one Tachyon User is found in the context subject");
    }
    return userSet.iterator().next();
  }

  /**
   * Logs in based on the LoginModules.
   *
   * @param conf Tachyon configuration
   * @return the login user
   * @throws IOException if login fails
   */
  private static User login(TachyonConf conf, String appName) throws IOException {
    AuthType authType = conf.getEnum(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.class);
    checkSecurityEnabled(authType);

    try {
      Subject subject = new Subject();

      LoginContext loginContext = new LoginContext(
          appName != null ? appName : authType.getAuthName(),
          subject, null, new TachyonJaasConfiguration());
      loginContext.login();

      Set<User> userSet = subject.getPrincipals(User.class);
      if (userSet.isEmpty()) {
        throw new LoginException("No Tachyon User is found.");
      }
      if (userSet.size() > 1) {
        throw new LoginException("More than one Tachyon User is found");
      }
      return userSet.iterator().next();
    } catch (LoginException e) {
      throw new IOException("Fail to login", e);
    }
  }

  public static void loginByKerberosKeytab(TachyonConf conf, String principal, String keytab)
      throws IOException {
    TachyonJaasConfiguration.setKerberosJaasOptions(principal, keytab);

    sLoginUser = login(conf, AuthType.KERBEROS.getAuthName() + "-" + TachyonJaasConfiguration
        .KERBEROS_USE_KEYTAB);
  }

  /**
   * Checks whether Tachyon is running in secure mode, such as SIMPLE, KERBEROS, CUSTOM.
   *
   * @param authType the authentication type in configuration
   */
  private static void checkSecurityEnabled(AuthType authType) {
    if (authType != AuthType.SIMPLE && authType != AuthType.CUSTOM && authType != AuthType
        .KERBEROS) {
      throw new UnsupportedOperationException("User is not supported in " + authType.getAuthName()
          + " mode");
    }
  }
}
