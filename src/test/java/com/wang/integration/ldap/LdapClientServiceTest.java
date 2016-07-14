package com.wang.integration.ldap;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.util.Assert;

import com.wang.integration.ldap.LdapClient;
import com.wang.integration.ldap.LdapConfig;
import com.wang.integration.ldap.LdapSearch;

public class LdapClientServiceTest {
	private static Logger logger = Logger.getLogger(LdapClientServiceTest.class.getName());

	String url = "ldap://ldap.dev.wang.com";
	String bindDn = "cn=Manager,dc=dev.wang,dc=com";
	String password = "123456";
	String baseDn = "dc=dev.wang,dc=com";

	String usersBaseDn = "ou=People";
	String uidQualifier = "uid";
	String passwordAttr = "userPassword";

	String groupBaseDn = "ou=Group";
	String groupQualifier = "cn";

	LdapClient ldapClient = null;

	@Before
	public void initContext() {
		try {
			LdapConfig ldapConfig = new LdapConfig();
			ldapConfig.setHost(url);
			ldapConfig.setBindDn(bindDn);
			ldapConfig.setPassword(password);
			ldapConfig.setBaseDn(baseDn);
			ldapClient = new LdapClient(ldapConfig);
		}
		catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	protected List<Map<String, Object>> search(String critia, String group) throws NamingException {
		LdapSearch ldapSearch = new LdapSearch();
		ldapSearch.setSearchBaseDn(usersBaseDn);
		ldapSearch.setQualifier(uidQualifier);

		LdapSearch ldapSearchGroup = new LdapSearch();
		ldapSearchGroup.setSearchBaseDn(groupBaseDn);
		ldapSearchGroup.setQualifier(groupQualifier);

		List<Map<String, Object>> answer = ldapClient.search(ldapSearch, critia, ldapSearchGroup, group);

		return answer;
	}

	@Test
	public void testSearch() throws NamingException {
		List<Map<String, Object>> answer = search("crm", "crmUsers");

		Assert.notNull(answer);
		String key = (String) answer.get(0).get("uid");
		Assert.isTrue(key.contains("crm"));
	}

	@Test
	public void testModify() throws NamingException {
		List<Map<String, Object>> answer = search("crm", "crmUsers");
		Assert.notNull(answer);
		String key = (String) answer.get(0).get("uid");

		Map<String, Object> password = new HashMap<String, Object>();
		password.put(passwordAttr, "password");
		ldapClient.update(password, key);
	}

	@After
	public void destroyContext() {
		if (ldapClient != null) {
			try {
				logger.info("关闭链接");
				ldapClient.close();
			}
			catch (Exception e) {

			}
		}
	}
}
