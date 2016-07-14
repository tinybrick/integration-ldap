package com.wang.integration.ldap;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.wang.integration.ldap.IDirectoryService;
import com.wang.integration.ldap.configure.LdapClientConfiguration;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = LdapClientConfiguration.class)
public class HtcheLdapServiceTest {
	@Autowired IDirectoryService htcheLdapService;

	@Test
	public void testHtcheLdapServiceVerifyUser() throws Exception {
		Assert.assertTrue(htcheLdapService.verifyUser("crm", "123456"));
	}

	@Test
	public void testHtcheLdapServiceVerifyGroup() throws Exception {
		Assert.assertTrue(htcheLdapService.inGroup("crm", "crmUsers"));
	}

	@Test
	public void testHtcheLdapServiceByMobile() throws Exception {
		Assert.assertNotNull(htcheLdapService.getByMobile("18665567662", "crmUsers"));
	}
}
