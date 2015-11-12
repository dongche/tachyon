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

package tachyon.security.login;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import tachyon.security.TachyonMiniKdc;
import tachyon.security.User;

/**
 * Unit test for the login modules defined in {@link tachyon.security.login.TachyonLoginModule} and
 * used in {@link tachyon.security.login.TachyonJaasConfiguration}
 */
public class LoginModuleTest {

  private static TachyonMiniKdc sTachyonMiniKdc;

  @BeforeClass
  public static void beforeClass() throws Exception {
    sTachyonMiniKdc = TachyonMiniKdc.getTachyonMiniKdc();
  }

  @AfterClass
  public static void afterClass() throws Exception {
    sTachyonMiniKdc.stop();
  }

  /**
   * This test verify whether the simple login works in JAAS framework.
   * Simple mode login get the OS user and convert to Tachyon user.
   * @throws Exception
   */
  @Test
  public void simpleLoginTest() throws Exception {
    String clazzName = TachyonJaasProperties.OS_PRINCIPAL_CLASS_NAME;
    @SuppressWarnings("unchecked")
    Class<? extends Principal> clazz = (Class<? extends Principal>) ClassLoader
        .getSystemClassLoader().loadClass(clazzName);
    Subject subject = new Subject();

    // login, add OS user into subject, and add corresponding Tachyon user into subject
    LoginContext loginContext = new LoginContext("simple", subject, null,
        new TachyonJaasConfiguration());
    loginContext.login();

    // verify whether OS user and Tachyon user is added.
    Assert.assertFalse(subject.getPrincipals(clazz).isEmpty());
    Assert.assertFalse(subject.getPrincipals(User.class).isEmpty());

    // logout and verify the user is removed
    loginContext.logout();
    Assert.assertTrue(subject.getPrincipals(User.class).isEmpty());
  }

  @Test
  public void kerberosLoginFromKeytabTest() throws Exception {
    Subject subject = new Subject();

    // login, add Kerberos user into subject, and add corresponding Tachyon user into subject
    TachyonJaasConfiguration.setKerberosJaasOptions(TachyonMiniKdc.TACHYON_CLIENT_USER_1,
        sTachyonMiniKdc.getKeytab(TachyonMiniKdc.TACHYON_CLIENT_USER_1));

    LoginContext loginContext = new LoginContext("kerberos-keytab", subject, null,
        new TachyonJaasConfiguration());
    loginContext.login();

    // verify whether Kerberos user and Tachyon user is added.
    Assert.assertFalse(subject.getPrincipals(KerberosPrincipal.class).isEmpty());
    Assert.assertFalse(subject.getPrincipals(User.class).isEmpty());

    // logout and verify the user is removed
    loginContext.logout();
    Assert.assertTrue(subject.getPrincipals(User.class).isEmpty());
  }

  @Ignore
  @Test
  public void kerberosLoginFromCacheTest() throws Exception {
    Subject subject = new Subject();

    // prepare
    List<String> commands = new ArrayList<String>();
    commands.add("klist");
    ProcessBuilder builder = new ProcessBuilder(commands);
    String xxx = sTachyonMiniKdc.getConfPath();
    builder.environment().put("KRB5_CONFIG", sTachyonMiniKdc.getConfPath());
    Process process = builder.start();
    process.waitFor();
    BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getErrorStream()));
    String line = stdInput.readLine();
    BufferedReader stdInput1 = new BufferedReader(new InputStreamReader(process.getInputStream()));
    String line1 = stdInput.readLine();
    if (process.exitValue() != 0) {
      //throw new IOException("can not kinit kerberos");
    }

    // login, add Kerberos user into subject, and add corresponding Tachyon user into subject
    LoginContext loginContext = new LoginContext("kerberos", subject, null,
        new TachyonJaasConfiguration());
    loginContext.login();

    // verify whether Kerberos user and Tachyon user is added.
    Assert.assertFalse(subject.getPrincipals(KerberosPrincipal.class).isEmpty());
    Assert.assertFalse(subject.getPrincipals(User.class).isEmpty());

    // logout and verify the user is removed
    loginContext.logout();
    Assert.assertTrue(subject.getPrincipals(User.class).isEmpty());
  }
}
