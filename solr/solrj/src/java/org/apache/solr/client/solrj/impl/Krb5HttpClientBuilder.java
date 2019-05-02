/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.solr.client.solrj.impl;

import java.lang.invoke.MethodHandles;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.cookie.CookieSpecProvider;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Kerberos-enabled SolrHttpClientBuilder
 */
public class Krb5HttpClientBuilder implements HttpClientBuilderFactory {

  private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  public static final String LOGIN_CONFIG_PROP = "java.security.auth.login.config";
  public static final String USE_SUBJECT_CREDS_PROP = "javax.security.auth.useSubjectCredsOnly";
  public static final boolean DEFAULT_USE_SYSTEM_LOGIN_CONFIG = true;

  private static Configuration jaasConfig = new SolrJaasConfiguration();

  private boolean useSystemLoginConfig;

  public Krb5HttpClientBuilder() {
    this(DEFAULT_USE_SYSTEM_LOGIN_CONFIG);
  }

  public Krb5HttpClientBuilder(boolean useSystemLoginConfig) {
    this.useSystemLoginConfig = useSystemLoginConfig;
  }

  /**
   * The jaasConfig is static, which makes it problematic for testing in the same jvm. Call this
   * function to regenerate the static config (this is not thread safe). Note: only used for tests
   */
  public static void regenerateJaasConfiguration() {
    jaasConfig = new SolrJaasConfiguration();
  }

  public SolrHttpClientBuilder getBuilder() {
    return getBuilder(HttpClientUtil.getHttpClientBuilder());
  }

  public void close() {
    HttpClientUtil.removeRequestInterceptor(bufferedEntityInterceptor);
  }

  @Override
  public SolrHttpClientBuilder getHttpClientBuilder(Optional<SolrHttpClientBuilder> builder) {
    return builder.isPresent() ? getBuilder(builder.get()) : getBuilder();
  }

  public SolrHttpClientBuilder getBuilder(SolrHttpClientBuilder builder) {
    if (useSystemLoginConfig && System.getProperty(LOGIN_CONFIG_PROP) != null) {
      String configValue = System.getProperty(LOGIN_CONFIG_PROP);
      logger.info("Setting up SPNego auth with config: " + configValue);
      
      String useSubjectCredsVal = System.getProperty(USE_SUBJECT_CREDS_PROP);

      // "javax.security.auth.useSubjectCredsOnly" should be false so that the underlying
      // authentication mechanism can load the credentials from the JAAS configuration.
      if (useSubjectCredsVal == null) {
        System.setProperty(USE_SUBJECT_CREDS_PROP, "false");
      } else if (!useSubjectCredsVal.toLowerCase(Locale.ROOT).equals("false")) {
        // Don't overwrite the prop value if it's already been written to something else,
        // but log because it is likely the Credentials won't be loaded correctly.
        logger.warn("System Property: {} set to: {} not false. " + 
          "SPNego authentication may not be successful.", USE_SUBJECT_CREDS_PROP, useSubjectCredsVal);
      }

      Configuration.setConfiguration(jaasConfig);
      // Enable only SPNEGO authentication scheme.  
      builder = configureBuilderForSPNego(builder);
    } else if (useSystemLoginConfig) {
      logger.warn("{} was constructed without either specifying system property '{}' " +
          "or indicating that this property should not be used",
          getClass().getName(), LOGIN_CONFIG_PROP);
    } else {
      logger.info("SPNego auth will use Subject in calling access controller context");
      // Enable only SPNEGO authentication scheme.  
      builder = configureBuilderForSPNego(builder);
    }
    
    return builder;
  }

  private SolrHttpClientBuilder configureBuilderForSPNego(SolrHttpClientBuilder builder) {
    // Set the authentication scheme registry to SPNego only
    builder.setAuthSchemeRegistryProvider(() -> {
      Lookup<AuthSchemeProvider> authProviders = RegistryBuilder.<AuthSchemeProvider>create()
          .register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory(true, false)).build();
      return authProviders;
    });

    HttpClientUtil.setCookiePolicy(SolrPortAwareCookieSpecFactory.POLICY_NAME);
    builder.setCookieSpecRegistryProvider(() -> {
      SolrPortAwareCookieSpecFactory cookieFactory = new SolrPortAwareCookieSpecFactory();

      Lookup<CookieSpecProvider> cookieRegistry = RegistryBuilder.<CookieSpecProvider>create()
          .register(SolrPortAwareCookieSpecFactory.POLICY_NAME, cookieFactory).build();

      return cookieRegistry;
    });

    // Get the credentials from the JAAS configuration rather than here
    Credentials useJaasCreds = new Credentials() {
      public String getPassword() {
        return null;
      }

      public Principal getUserPrincipal() {
        return null;
      }
    };
    builder.setDefaultCredentialsProvider(() -> {
      CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
      credentialsProvider.setCredentials(AuthScope.ANY, useJaasCreds);
      return credentialsProvider;
    });

    HttpClientUtil.addRequestInterceptor(bufferedEntityInterceptor);

    return builder;
  }

  // Set a buffered entity based request interceptor
  private HttpRequestInterceptor bufferedEntityInterceptor = (request, context) -> {
    if (request instanceof HttpEntityEnclosingRequest) {
      HttpEntityEnclosingRequest enclosingRequest = ((HttpEntityEnclosingRequest) request);
      HttpEntity requestEntity = enclosingRequest.getEntity();
      enclosingRequest.setEntity(new BufferedHttpEntity(requestEntity));
    }
  };

  private static class SolrJaasConfiguration extends javax.security.auth.login.Configuration {

    public static final String JGSS_KRB5_INIT = "com.sun.security.jgss.krb5.initiate";
    public static final String JGSS_INIT = "com.sun.security.jgss.initiate";
    public static final String SOLR_KRB_APPNAME = "solr.kerberos.jaas.appname";
    public static final String DEFAULT_SOLR_KRB_APPNAME = "Client";

    private javax.security.auth.login.Configuration baseConfig;

    // the com.sun.security.jgss appNames
    private Set<String> initiateAppNames = new HashSet<>(Arrays.asList(JGSS_KRB5_INIT, JGSS_INIT));

    public SolrJaasConfiguration() {
      try {
        this.baseConfig = Configuration.getConfiguration();
      } catch (SecurityException e) {
        this.baseConfig = null;
      }
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
      if (baseConfig == null)
        return null;

      logger.debug("Login prop: {}", System.getProperty(LOGIN_CONFIG_PROP));

      String clientAppName = System.getProperty(SOLR_KRB_APPNAME, DEFAULT_SOLR_KRB_APPNAME);
      if (initiateAppNames.contains(appName)) {
        logger.debug("Using AppConfigurationEntry for appName '{}' instead of: {}", 
          clientAppName, appName);
        return baseConfig.getAppConfigurationEntry(clientAppName);
      }
      return baseConfig.getAppConfigurationEntry(appName);
    }
  }
}
