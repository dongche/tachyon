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

package tachyon.security.authentication;

import java.lang.reflect.Field;
import java.net.InetSocketAddress;

import javax.security.sasl.AuthenticationException;
import javax.security.sasl.SaslException;

import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.server.TThreadPoolServer;
import org.apache.thrift.transport.TServerSocket;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;
import org.apache.thrift.transport.TTransportFactory;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import tachyon.Constants;
import tachyon.conf.TachyonConf;
import tachyon.security.LoginUser;
import tachyon.security.TachyonMiniKdc;
import tachyon.util.network.NetworkAddressUtils;

/**
 * Unit test for methods of {@link AuthenticationUtils}
 *
 * In order to test methods that return kinds of TTransport for connection in different mode, we
 * build Thrift servers and clients with specific TTransport, and let them connect.
 */
public class AuthenticationUtilsTest {

  private TThreadPoolServer mServer;
  private TachyonConf mTachyonConf;
  private InetSocketAddress mServerAddress;
  private TServerSocket mServerTSocket;
  private TSocket mClientTSocket;

  @Rule
  public ExpectedException mThrown = ExpectedException.none();

  @Before
  public void before() throws Exception {
    mTachyonConf = new TachyonConf();
    // Use port 0 to assign each test case an available port (possibly different)
    mServerTSocket = new TServerSocket(new InetSocketAddress("localhost", 0));
    int port = NetworkAddressUtils.getThriftPort(mServerTSocket);
    mServerAddress = new InetSocketAddress("localhost", port);
    mClientTSocket = AuthenticationUtils.createTSocket(mServerAddress);
    clearLoginUser();
  }

  private void clearLoginUser() throws Exception {
    Field field = LoginUser.class.getDeclaredField("sLoginUser");
    field.setAccessible(true);
    field.set(null, null);
  }

  /**
   * In NOSASL mode, the TTransport used should be the same as Tachyon original code.
   */
  @Test
  public void nosaslAuthenticationTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "NOSASL");

    // start server
    startServerThread();

    // create client and connect to server
    TTransport client = AuthenticationUtils.getClientTransport(mTachyonConf, mServerAddress);
    client.open();
    Assert.assertTrue(client.isOpen());

    // clean up
    client.close();
    mServer.stop();
  }

  /**
   * In SIMPLE mode, the TTransport mechanism is PLAIN. When server authenticate the connected
   * client user, it use {@link tachyon.security.authentication.SimpleAuthenticationProviderImpl}.
   */
  @Test
  public void simpleAuthenticationTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "SIMPLE");

    // start server
    startServerThread();

    // when connecting, authentication happens. It is a no-op in Simple mode.
    TTransport client =
        PlainSaslUtils.getPlainClientTransport("anyone", "whatever", mClientTSocket);
    client.open();
    Assert.assertTrue(client.isOpen());

    // clean up
    client.close();
    mServer.stop();
  }

  /**
   * In SIMPLE mode, if client's username is null, an exception should be thrown in client side.
   */
  @Test
  public void simpleAuthenticationNullUserTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "SIMPLE");

    // check case that user is null
    mThrown.expect(SaslException.class);
    mThrown.expectMessage("PLAIN: authorization ID and password must be specified");
    TTransport client = PlainSaslUtils.getPlainClientTransport(null, "whatever", mClientTSocket);
  }

  /**
   * In SIMPLE mode, if client's password is null, an exception should be thrown in client side.
   */
  @Test
  public void simpleAuthenticationNullPasswordTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "SIMPLE");

    // check case that password is null
    mThrown.expect(SaslException.class);
    mThrown.expectMessage("PLAIN: authorization ID and password must be specified");
    TTransport client = PlainSaslUtils.getPlainClientTransport("anyone", null, mClientTSocket);
  }

  /**
   * In SIMPLE mode, if client's username is empty, an exception should be thrown in server side.
   */
  @Test
  public void simpleAuthenticationEmptyUserTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "SIMPLE");

    // start server
    startServerThread();

    // check case that user is empty
    mThrown.expect(TTransportException.class);
    mThrown.expectMessage("Peer indicated failure: Plain authentication failed: No authentication"
        + " identity provided");
    TTransport client = PlainSaslUtils.getPlainClientTransport("", "whatever", mClientTSocket);
    try {
      client.open();
    } finally {
      mServer.stop();
    }
  }

  /**
   * In SIMPLE mode, if client's password is empty, an exception should be thrown in server side.
   * Although password is actually not used and we do not really authenticate the user in SIMPLE
   * mode, we need the Plain SASL server has ability to check empty password.
   */
  @Test
  public void simpleAuthenticationEmptyPasswordTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "SIMPLE");

    // start server
    startServerThread();

    // check case that password is empty
    mThrown.expect(TTransportException.class);
    mThrown.expectMessage("Peer indicated failure: Plain authentication failed: No password "
        + "provided");
    TTransport client = PlainSaslUtils.getPlainClientTransport("anyone", "", mClientTSocket);
    try {
      client.open();
    } finally {
      mServer.stop();
    }
  }

  /**
   * In CUSTOM mode, the TTransport mechanism is PLAIN. When server authenticate the connected
   * client user, it use configured AuthenticationProvider. If the username:password pair matches, a
   * connection should be built.
   */
  @Test
  public void customAuthenticationExactNamePasswordMatchTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "CUSTOM");
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_CUSTOM_PROVIDER,
        ExactlyMatchAuthenticationProvider.class.getName());

    // start server
    startServerThread();

    // when connecting, authentication happens. User's name:pwd pair matches and auth pass.
    TTransport client =
        PlainSaslUtils.getPlainClientTransport("tachyon", "correct-password", mClientTSocket);
    client.open();
    Assert.assertTrue(client.isOpen());

    // clean up
    client.close();
    mServer.stop();
  }

  /**
   * In CUSTOM mode, If the username:password pair does not match based on the configured
   * AuthenticationProvider, an exception should be thrown in server side.
   */
  @Test
  public void customAuthenticationExactNamePasswordNotMatchTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "CUSTOM");
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_CUSTOM_PROVIDER,
        ExactlyMatchAuthenticationProvider.class.getName());

    // start server
    startServerThread();

    // User with wrong password can not pass auth, and throw exception.
    TTransport wrongClient =
        PlainSaslUtils.getPlainClientTransport("tachyon", "wrong-password", mClientTSocket);
    mThrown.expect(TTransportException.class);
    mThrown.expectMessage("Peer indicated failure: Plain authentication failed: "
        + "User authentication fails");
    try {
      wrongClient.open();
    } finally {
      mServer.stop();
    }
  }

  /**
   * In CUSTOM mode, if client's username is null, an exception should be thrown in client side.
   */
  @Test
  public void customAuthenticationNullUserTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "CUSTOM");

    // check case that user is null
    mThrown.expect(SaslException.class);
    mThrown.expectMessage("PLAIN: authorization ID and password must be specified");
    TTransport client =
        PlainSaslUtils.getPlainClientTransport(null, "correct-password", mClientTSocket);
  }

  /**
   * In CUSTOM mode, if client's password is null, an exception should be thrown in client side.
   */
  @Test
  public void customAuthenticationNullPasswordTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "CUSTOM");

    // check case that password is null
    mThrown.expect(SaslException.class);
    mThrown.expectMessage("PLAIN: authorization ID and password must be specified");
    TTransport client = PlainSaslUtils.getPlainClientTransport("tachyon", null, mClientTSocket);
  }

  /**
   * In CUSTOM mode, if client's username is empty, an exception should be thrown in server side.
   */
  @Test
  public void customAuthenticationEmptyUserTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "CUSTOM");
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_CUSTOM_PROVIDER,
        ExactlyMatchAuthenticationProvider.class.getName());

    // start server
    startServerThread();

    // check case that user is empty
    mThrown.expect(TTransportException.class);
    mThrown.expectMessage("Peer indicated failure: Plain authentication failed: No authentication"
        + " identity provided");
    TTransport client =
        PlainSaslUtils.getPlainClientTransport("", "correct-password", mClientTSocket);
    try {
      client.open();
    } finally {
      mServer.stop();
    }
  }

  /**
   * In CUSTOM mode, if client's password is empty, an exception should be thrown in server side.
   */
  @Test
  public void customAuthenticationEmptyPasswordTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "CUSTOM");
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_CUSTOM_PROVIDER,
        ExactlyMatchAuthenticationProvider.class.getName());

    // start server
    startServerThread();

    // check case that password is empty
    mThrown.expect(TTransportException.class);
    mThrown.expectMessage("Peer indicated failure: Plain authentication failed: No password "
        + "provided");
    TTransport client = PlainSaslUtils.getPlainClientTransport("tachyon", "", mClientTSocket);
    try {
      client.open();
    } finally {
      mServer.stop();
    }
  }

  /**
   * In KERBEROS mode
   */
  @Test
  public void kerberosAuthenticationTest() throws Exception {
    mTachyonConf.set(Constants.SECURITY_AUTHENTICATION_TYPE, "KERBEROS");
    mTachyonConf.set(Constants.SECURITY_SERVER_KERBEROS_PRINCIPAL,
        sTachyonMiniKdc.getTachyonServicePrincipal());
    mTachyonConf.set(Constants.SECURITY_SERVER_KERBEROS_KEYTAB,
        sTachyonMiniKdc.getKeytab(sTachyonMiniKdc.getTachyonServicePrincipal()));

    // start server
    startServerThread();

    // when connecting, authentication happens.
    clearLoginUser();
    LoginUser.loginByKerberosKeytab(mTachyonConf, TachyonMiniKdc.TACHYON_CLIENT_USER_1,
        sTachyonMiniKdc.getKeytab(TachyonMiniKdc.TACHYON_CLIENT_USER_1));
    TTransport client = KerberosSaslUtils.getKerberosClientTransport(mTachyonConf,
        sTachyonMiniKdc.getFullTachyonServicePrincipal(), null, mClientTSocket);
    client.open();
    Assert.assertTrue(client.isOpen());

    // clean up
    client.close();
    mServer.stop();
  }

  private static TachyonMiniKdc sTachyonMiniKdc;

  @BeforeClass
  public static void beforeClass() throws Exception {
    sTachyonMiniKdc = TachyonMiniKdc.getTachyonMiniKdc();
  }

  @AfterClass
  public static void afterClass() throws Exception {
    sTachyonMiniKdc.stop();
  }

  private void startServerThread() throws Exception {
    // create args and use them to build a Thrift TServer
    TTransportFactory tTransportFactory =
        AuthenticationUtils.getServerTransportFactory(mTachyonConf);

    mServer =
        new TThreadPoolServer(new TThreadPoolServer.Args(mServerTSocket).maxWorkerThreads(2)
            .minWorkerThreads(1).processor(null).transportFactory(tTransportFactory)
            .protocolFactory(new TBinaryProtocol.Factory(true, true)));

    // start the server in a new thread
    Thread serverThread = new Thread(new Runnable() {
      @Override
      public void run() {
        mServer.serve();
      }
    });

    serverThread.start();

    // ensure server is running, and break if it does not start serving in 2 seconds.
    int count = 40;
    while (!mServer.isServing() && serverThread.isAlive()) {
      if (count <= 0) {
        throw new RuntimeException("TThreadPoolServer does not start serving");
      }
      Thread.sleep(50);
      count --;
    }
  }

  /**
   * This customized authentication provider is used in CUSTOM mode. It authenticate the user by
   * verifying the specific username:password pair.
   */
  public static class ExactlyMatchAuthenticationProvider implements AuthenticationProvider {
    @Override
    public void authenticate(String user, String password) throws AuthenticationException {
      if (!user.equals("tachyon") || !password.equals("correct-password")) {
        throw new AuthenticationException("User authentication fails");
      }
    }
  }

}
