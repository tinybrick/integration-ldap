package com.wang.integration.ldap;

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;

import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.springframework.context.SmartLifecycle;

import com.wang.utils.crypto.Codec;
import com.wang.utils.crypto.MD5;
import com.wang.utils.crypto.SHA1;

public class HtcheLdapService implements SmartLifecycle, IDirectoryService {
	private String usersBaseDn = "ou=people";
	private String uidQualifier = "uid";
	private String passwordAttr = "userPassword";
	private String mobileAttr = "mobile";

	private String groupBaseDn = "ou=group";
	private String groupQualifier = "cn";

	public String getUsersBaseDn() {
		return usersBaseDn;
	}

	public void setUsersBaseDn(String usersBaseDn) {
		this.usersBaseDn = usersBaseDn;
	}

	public String getUidQualifier() {
		return uidQualifier;
	}

	public void setUidQualifier(String uidQualifier) {
		this.uidQualifier = uidQualifier;
	}

	public String getPasswordAttr() {
		return passwordAttr;
	}

	public void setPasswordAttr(String passwordAttr) {
		this.passwordAttr = passwordAttr;
	}

	public String getGroupBaseDn() {
		return groupBaseDn;
	}

	public void setGroupBaseDn(String groupBaseDn) {
		this.groupBaseDn = groupBaseDn;
	}

	public String getGroupQualifier() {
		return groupQualifier;
	}

	public void setGroupQualifier(String groupQualifier) {
		this.groupQualifier = groupQualifier;
	}

	private static enum ENCRYPTION_METHOD {
		MD5("{MD5}"), SHA("{SHA}");

		private String text;

		ENCRYPTION_METHOD(String text) {
			this.text = text;
		}

		public String getText() {
			return this.text;
		}

		public static ENCRYPTION_METHOD fromString(String text) {
			if (text != null) {
				for (ENCRYPTION_METHOD b : ENCRYPTION_METHOD.values()) {
					if (text.equalsIgnoreCase(b.text)) {
						return b;
					}
				}
			}
			return null;
		}
	}

	Logger logger = Logger.getLogger(this.getClass());

	private static LdapClient ldapClient = null;
	LdapConfig ldapConfig;

	public HtcheLdapService(LdapConfig config) {
		this.ldapConfig = config;
	}

	private synchronized void init() throws UnsupportedEncodingException, NamingException {
		if (null == ldapClient) {
			logger.info("LdapClient is going to be init.");
			ldapClient = new LdapClient(ldapConfig);
		}
	}

	/* (non-Javadoc)
	 * @see com.wang.integration.ldap.IDirectoryService#detail(java.lang.String)
	 */
	@Override
	public List<Map<String, Object>> detail(String username) throws Exception {
		return detail(username, null);
	}

	/* (non-Javadoc)
	 * @see com.wang.integration.ldap.IDirectoryService#detail(java.lang.String, java.lang.String)
	 */
	@Override
	public List<Map<String, Object>> detail(String username, String group) throws Exception {
		try {
			init();

			logger.debug("Searching is going to be in " + usersBaseDn + " with " + uidQualifier + "=" + username);
			LdapSearch search = generateSearchCondition(usersBaseDn, uidQualifier, uidQualifier);

			LdapSearch searchGroup = null;
			if (null != group) {
				logger.debug("Searching within " + groupBaseDn + " with " + groupQualifier + "=" + group);
				searchGroup = generateSearchCondition(groupBaseDn, groupQualifier, groupQualifier);
			}

			return ldapClient.search(search, username, searchGroup, group);
		}
		catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		}
	}

	/* (non-Javadoc)
	 * @see com.wang.integration.ldap.IDirectoryService#verifyUser(java.lang.String, java.lang.String)
	 */
	@Override
	public boolean verifyUser(String username, String password) throws Exception {
		return verifyUser(username, password, null);
	}

	/* (non-Javadoc)
	 * @see com.wang.integration.ldap.IDirectoryService#verifyUser(java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public boolean verifyUser(String username, String password, String group) throws Exception {
		if (null == password) {
			logger.debug("Password is not expected to be null");
			return false;
		}

		try {
			List<Map<String, Object>> entries = detail(username, group);
			if (null == entries) {
				logger.debug("No entry has been found");
				return false;
			}
			else {
				Map<String, Object> entry = entries.get(0);
				logger.debug("One entry " + entry.get(uidQualifier) + " is found!");

				//Map<String, Object> info = entries.get(name);
				/*if (null == info) {
					logger.warn(name + " is an enpty item?");
					return false;
				}
				else {*/
				Object passwordObject = entry.get(passwordAttr);
				String passwd = (passwordObject instanceof byte[]) ? new String((byte[]) passwordObject, "UTF-8")
						: (String) passwordObject;
				return checkPassword(passwd, password);
				//}
			}

		}
		catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		}
	}

	private boolean checkPassword(String password, String expectation) throws UnsupportedEncodingException {
		if (null == password)
			return false;

		if (password.startsWith(ENCRYPTION_METHOD.MD5.getText())) {
			logger.debug(ENCRYPTION_METHOD.MD5.getText() + " encryption method applied");
			return password.equals(ENCRYPTION_METHOD.MD5.getText() + encrypt(expectation, ENCRYPTION_METHOD.MD5));
		}
		else if (password.startsWith(ENCRYPTION_METHOD.SHA.getText())) {
			logger.debug(ENCRYPTION_METHOD.SHA.getText() + " encryption method applied");
			return password.equals(ENCRYPTION_METHOD.SHA.getText() + encrypt(expectation, ENCRYPTION_METHOD.SHA));
		}
		else {
			return password.equals(expectation);
		}
	}

	private String encrypt(String str, ENCRYPTION_METHOD method) throws UnsupportedEncodingException {
		switch (method) {
			case MD5:
				return Codec.toBase64(hexToBytes(MD5.hash(str)));
			case SHA:
				return Codec.toBase64(hexToBytes(SHA1.hash(str))); //{SHA}fEqNCco3Yq9h5ZUglD3CZJT4lBs=
			default:
				throw new UnsupportedOperationException("Unsupported encrypt method");
		}
	}

	/* (non-Javadoc)
	 * @see com.wang.integration.ldap.IDirectoryService#inGroup(java.lang.String, java.lang.String)
	 */
	@Override
	public boolean inGroup(String username, String group) throws Exception {
		return inGroup(username, null, group);
	}

	/* (non-Javadoc)
	 * @see com.wang.integration.ldap.IDirectoryService#inGroup(java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public boolean inGroup(String username, String password, String group) throws Exception {
		try {
			init();

			if (null != password) {
				if (!verifyUser(username, password))
					return false;
			}

			LdapSearch searchUser = generateSearchCondition(usersBaseDn, uidQualifier, uidQualifier);
			LdapSearch searchGroup = generateSearchCondition(groupBaseDn, groupQualifier, groupQualifier);

			if (null == ldapClient.search(searchUser, username, searchGroup, group))
				return false;
			else
				return true;
		}
		catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		}
	}

	public static byte[] hexToBytes(String s) {
		String s2;
		byte[] b = new byte[s.length() / 2];
		int i;
		for (i = 0; i < s.length() / 2; i++) {
			s2 = s.substring(i * 2, i * 2 + 2);
			b[i] = (byte) (Integer.parseInt(s2, 16) & 0xff);
		}
		return b;
	}

	/*private static LdapSearch generateSearchCondition(String usersBaseDn, String uid) {
		return generateSearchCondition(usersBaseDn, uid, uid);
	}*/

	private static LdapSearch generateSearchCondition(String usersBaseDn, String uid, String qualifier) {
		LdapSearch search = new LdapSearch();
		search.setQualifier(qualifier);
		search.setUid(uid);
		search.setSearchBaseDn(usersBaseDn);
		return search;
	}

	@Override
	public void start() {
		try {
			init();
		}
		catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw new RuntimeException(e);
		}
	}

	@Override
	public void stop() {
		ldapClient.close();
	}

	@Override
	public boolean isRunning() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public int getPhase() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public boolean isAutoStartup() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void stop(Runnable callback) {
		// TODO Auto-generated method stub

	}

	@Override
	public List<Map<String, Object>> getByMobile(String mobile) throws Exception {
		return getByMobile(mobile, null);
	}

	@Override
	public List<Map<String, Object>> getByMobile(String mobile, String group) throws Exception {
		try {
			init();

			logger.debug("Searching is going to be in " + usersBaseDn + " with " + mobileAttr + "=" + mobile);
			LdapSearch search = generateSearchCondition(usersBaseDn, uidQualifier, mobileAttr);

			LdapSearch searchGroup = null;
			if (null != group) {
				logger.debug("Searching within " + groupBaseDn + " with " + groupQualifier + "=" + group);
				searchGroup = generateSearchCondition(groupBaseDn, groupQualifier, groupQualifier);
			}

			return ldapClient.search(search, mobile, searchGroup, group);
		}
		catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		}
	}
}
