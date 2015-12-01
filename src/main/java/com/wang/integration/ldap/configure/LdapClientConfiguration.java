package com.wang.integration.ldap.configure;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

import com.wang.integration.ldap.HtcheLdapService;
import com.wang.integration.ldap.IDirectoryService;
import com.wang.integration.ldap.LdapConfig;

@Configuration
@ComponentScan
@EnableConfigurationProperties({ PropertySourcesPlaceholderConfigurer.class })
@PropertySource(value = "classpath:config/ldap.properties")
public class LdapClientConfiguration {
	Logger logger = Logger.getLogger(this.getClass());

	@Value("${ldap.connection.url}") String url;
	@Value("${ldap.connection.user}") String bindDn;
	@Value("${ldap.connection.password}") String password;
	@Value("${ldap.server.baseDn}") String baseDn;
	@Value("${ldap.server.search.usersBaseDn:ou=people}") String usersBaseDn;
	@Value("${ldap.server.search.uidQualifier:uid}") String uidQualifier;
	@Value("${ldap.server.search.passwordAttr:userPassword}") String passwordAttr;
	@Value("${ldap.server.search.groupBaseDn:ou=group}") String groupBaseDn;
	@Value("${ldap.server.search.groupQualifier:cn}") String groupQualifier;

	@Bean(destroyMethod = "stop")
	public IDirectoryService htcheLdapService() {
		LdapConfig ldapConfig = new LdapConfig();
		ldapConfig.setHost(url);
		ldapConfig.setBindDn(bindDn);
		ldapConfig.setPassword(password);
		ldapConfig.setBaseDn(baseDn);

		HtcheLdapService htcheLdapService = new HtcheLdapService(ldapConfig);

		htcheLdapService.setUsersBaseDn(usersBaseDn);
		htcheLdapService.setUidQualifier(uidQualifier);
		htcheLdapService.setPasswordAttr(passwordAttr);
		htcheLdapService.setGroupBaseDn(groupBaseDn);
		htcheLdapService.setGroupQualifier(groupQualifier);

		return htcheLdapService;
	}

}
