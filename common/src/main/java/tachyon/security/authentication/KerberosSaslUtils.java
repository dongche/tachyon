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

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;

import org.apache.thrift.transport.TSaslClientTransport;
import org.apache.thrift.transport.TSaslServerTransport;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;
import org.apache.thrift.transport.TTransportFactory;

import tachyon.Constants;
import tachyon.conf.TachyonConf;
import tachyon.security.LoginUser;
import tachyon.security.User;

/**
 * It provides methods to generate Kerberos transport for server and client.
 */
public class KerberosSaslUtils {

  private static final String MECHANISM = "GSSAPI";

  public static TTransportFactory getKerberosServerTransportFactory(TachyonConf conf) throws
      IOException {
    // fetch server principal and keytab
    String principal = conf.get(Constants.SECURITY_SERVER_KERBEROS_PRINCIPAL);
    String keytabFile = conf.get(Constants.SECURITY_SERVER_KERBEROS_KEYTAB);
    if (principal == null || principal.isEmpty()) {
      throw new SaslException("No server principal is provided");
    }
    if (keytabFile == null || principal.isEmpty()) {
      throw new SaslException("No server keytab is provided");
    }

    // login
    LoginUser.loginByKerberosKeytab(conf, principal, keytabFile);
    User user = LoginUser.get(conf);
    String[] names = splitKerberosName(user.getName());
    if (names.length != 3) {
      throw new SaslException("Kerberos principal should have 3 parts: " + user.getName());
    }

    // create server transport factory
    TSaslServerTransport.Factory factory = new TSaslServerTransport.Factory();
    factory.addServerDefinition(MECHANISM, names[0], names[1], null,
        new KerberosServerCallbackHandler());

    return new TDoAsTransportFactory(factory, user.getSubject());
  }

  public static TTransport getKerberosClientTransport(TachyonConf conf, String serverPrincipal,
      String serverHost, TTransport underlyingTransport) throws IOException {
    // TODO: use KerberosUtil to get server principal
    String[] names = splitKerberosName(serverPrincipal);
    if (names.length != 3) {
      throw new SaslException("Kerberos principal should have 3 parts: " + serverPrincipal);
    }

    // TODO: login from client keytab, if client side does not kinit.
    // get login user from kerberos cache
    User user = LoginUser.get(conf);

    // create client transport
    TTransport saslTransport = new TSaslClientTransport(MECHANISM, null, names[0], names[1],
        new HashMap<String, String>(), null, underlyingTransport);
    return new TDoAsTransport(saslTransport, user.getSubject());
  }

  private static String[] splitKerberosName(String fullName) {
    return fullName.split("[/@]");
  }

  public static class TDoAsTransport extends TTransport {
    private Subject mSubject;
    private TTransport mWrapped;

    public TDoAsTransport(TTransport wrapped, Subject subject) {
      mWrapped = wrapped;
      mSubject = subject;
    }

    @Override
    public void open() throws TTransportException {
      try {
        Subject.doAs(mSubject, new PrivilegedExceptionAction<Void>() {
          @Override
          public Void run() throws Exception {
            mWrapped.open();
            return null;
          }
        });
      } catch (Exception e) {
        throw new TTransportException(e.getMessage());
      }
    }

    @Override
    public void close() {
      mWrapped.close();
    }

    @Override
    public void write(byte[] buf) throws TTransportException {
      mWrapped.write(buf);
    }

    @Override
    public void write(byte[] buf, int off, int len) throws TTransportException {
      mWrapped.write(buf, off, len);
    }

    @Override
    public int read(byte[] buf, int off, int len) throws TTransportException {
      return mWrapped.read(buf, off, len);
    }

    @Override
    public int readAll(byte[] buf, int off, int len) throws TTransportException {
      return mWrapped.readAll(buf, off, len);
    }

    @Override
    public boolean isOpen() {
      return mWrapped.isOpen();
    }

    @Override
    public boolean peek() {
      return mWrapped.peek();
    }
  }

  public static class TDoAsTransportFactory extends TTransportFactory {
    private final TTransportFactory mWrapped;
    private final Subject mSubject;

    public TDoAsTransportFactory(TTransportFactory wrapped, Subject subject) {
      mWrapped = wrapped;
      mSubject = subject;
    }

    @Override
    public TTransport getTransport(final TTransport tTransport) {
      return Subject.doAs(mSubject, new PrivilegedAction<TTransport>() {
        @Override
        public TTransport run() {
          return mWrapped.getTransport(tTransport);
        }
      });
    }
  }

  public static class KerberosServerCallbackHandler implements CallbackHandler {

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
      AuthorizeCallback ac = null;
      for (Callback callback : callbacks) {
        if (callback instanceof AuthorizeCallback) {
          ac = (AuthorizeCallback) callback;
        } else {
          throw new UnsupportedCallbackException(callback,
              "Unrecognized SASL GSSAPI Callback");
        }
      }
      if (ac != null) {
        String authid = ac.getAuthenticationID();
        String authzid = ac.getAuthorizationID();
        if (authid.equals(authzid)) {
          ac.setAuthorized(true);
        } else {
          ac.setAuthorized(false);
        }
        if (ac.isAuthorized()) {
          ac.setAuthorizedID(authzid);
          // After verification succeeds, a user with this authz id will be set to a Threadlocal.
          PlainSaslServer.AuthorizedClientUser.set(authzid);
        }
      }
    }
  }
}
