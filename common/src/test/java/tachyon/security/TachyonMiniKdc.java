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

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.hadoop.minikdc.MiniKdc;

/**
 * A wrapper of {@link org.apache.hadoop.minikdc.MiniKdc} for use in Tachyon test.
 */
public class TachyonMiniKdc {

  //TODO: add more users when test cases become complex.
  // initialize a set of principals for test use
  public static final String TACHYON_SERVICE_PRINCIPAL = "tachyon";
  public static final String TACHYON_CLIENT_USER_1 = "user1";
  public static final String TACHYON_CLIENT_USER_2 = "user2";

  private File mWorkDir;
  private Properties mMiniKdcConf;
  private MiniKdc mMiniKdc;

  private Map<String, String> mUserPrincipalKeytab = new HashMap<String, String>();

  public static TachyonMiniKdc getTachyonMiniKdc() throws Exception {
    return new TachyonMiniKdc();
  }

  public TachyonMiniKdc() throws Exception {
    mWorkDir = new File(System.getProperty("test.dir", "target"));
    mMiniKdcConf = MiniKdc.createConf();

    System.clearProperty("java.security.krb5.kdc");
    System.clearProperty("java.security.krb5.realm");

    mMiniKdc = new MiniKdc(mMiniKdcConf, mWorkDir);
    mMiniKdc.start();

    initializeUserPrincipal(TACHYON_SERVICE_PRINCIPAL, TACHYON_CLIENT_USER_1,
        TACHYON_CLIENT_USER_2);
  }

  private void initializeUserPrincipal(String... principals) throws Exception {
    for (String principal : principals) {
      File keytab = new File(mWorkDir, principal + ".keytab");
      mMiniKdc.createPrincipal(keytab, principal);
      mUserPrincipalKeytab.put(principal, keytab.getPath());
    }
  }

  public String getKeytab(String principal) {
    return mUserPrincipalKeytab.get(principal);
  }

  public void stop() {
    mMiniKdc.stop();
  }
}
