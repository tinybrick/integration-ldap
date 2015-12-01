package com.wang.integration.ldap;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.apache.log4j.Logger;

public class LdapClient {
	private static Logger logger = Logger.getLogger(LdapClient.class.getName());

	private static final String AUTHENTICATION_METHOD = "simple";
	private static final String CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
	private static final String SEARCH_RESTRICT = "%restrict%";
	private static final String GROUP_MEMBER_QUALIFIER = "memberUid";
	//private static final String UID_QUALIFIER = "uid";

	LdapContext ldapCtx = null;

	public LdapClient(LdapContext ldapCtx) {
		this.ldapCtx = ldapCtx;
	}

	public LdapClient(Hashtable<String, String> env) throws NamingException {
		ldapCtx = new InitialLdapContext(env, null);
	}

	public LdapClient(LdapConfig ldapConfig) throws NamingException, UnsupportedEncodingException {
		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
		env.put(Context.SECURITY_AUTHENTICATION, AUTHENTICATION_METHOD);
		String baseDN = URLEncoder.encode(ldapConfig.getBaseDn(), "utf-8");
		env.put(Context.PROVIDER_URL, ldapConfig.getHost() + "/" + baseDN);
		env.put(Context.SECURITY_PRINCIPAL, ldapConfig.getBindDn());
		env.put(Context.SECURITY_CREDENTIALS, ldapConfig.getPassword());

		logger.info("Connecting to ldap...");
		ldapCtx = new InitialLdapContext(env, null);
		logger.info("Connection established.");
	}

	/*public void add(HashMap<String, Object> map, String dn) {
		try {
			Attributes attrs = new BasicAttributes();
			for (Map.Entry<String, Object> me : map.entrySet()) {
				attrs.put(me.getKey(), me.getValue());
			}

			Properties props = new Properties();
			props.load(LdapClientServiceTest.class.getResourceAsStream("/ldap.properties"));
			String objectclassStr = props.getProperty("ou.People.Objectclass");
			String[] objClassArr = objectclassStr.split(",");
			Attribute objclass = new BasicAttribute("objectClass");
			for (int i = 0; i < objClassArr.length; i++) {
				objclass.add(objClassArr[i]);
			}
			attrs.put(objclass);
			ldapCtx.createSubcontext(dn, attrs);
			logger.info("添加成功！");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}*/

	/* public void delete(LdapContext ldapCtx, String dn) {
		try {
			logger.info("删除开始");
			ldapCtx.destroySubcontext(dn);
			logger.info("删除成功... ...");
		}
		catch (Exception e) {
			logger.info("Exception in delete():" + e);
			e.printStackTrace();
		}
	} */

	public void update(Map<String, Object> map, String dn) throws NamingException {
		ModificationItem mods[] = new ModificationItem[map.entrySet().size()];
		int i = 0;
		for (Map.Entry<String, Object> me : map.entrySet()) {
			mods[i] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(me.getKey(), me.getValue()));
			i++;
		}
		ldapCtx.modifyAttributes(dn, mods);
	}

	/**
	 * 将 NamingEnumeration 转成 Map
	 * 
	 * @param dn
	 * @return
	 * @throws NamingException
	 */
	@SuppressWarnings("unchecked")
	private List<Map<String, Object>> toList(NamingEnumeration<SearchResult> dn) throws NamingException {
		List<Map<String, Object>> resultMap = null;

		if (null == dn)
			return null;

		while (dn.hasMoreElements()) {
			// 得到每一个返回值
			SearchResult sr = dn.next();
			//String dnName = sr.getNameInNamespace();
			Map<String, Object> attrMap = getAttributes(sr);

			if (null == resultMap)
				resultMap = new ArrayList<Map<String, Object>>();
			resultMap.add(attrMap);
		}

		return resultMap;
	}

	/**
	 * 查询
	 * 
	 * @param search
	 * @param restrict
	 * @param groups
	 * @param groupName
	 * @return
	 * @throws NamingException
	 * @throws Exception
	 */
	public List<Map<String, Object>> search(LdapSearch search, String restrict, LdapSearch groups, String groupName)
			throws NamingException {
		return internalQuery(search, restrict, groups, groupName);
	}

	private List<Map<String, Object>> internalQuery(LdapSearch search, String restrict, LdapSearch group,
			String groupName) throws NamingException {
		SearchControls searchCtls = new SearchControls();
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		String filter = null;
		if (null != search.getSearchFilter()) {
			filter = search.getSearchFilter().replace(SEARCH_RESTRICT, restrict);
		}
		else {
			filter = search.getQualifier() + "=" + restrict;
		}
		List<Map<String, Object>> answer = toList(this.ldapCtx.search(search.getSearchBaseDn(), filter, searchCtls));

		if (null != answer) {
			if (null != groupName && null != group) {
				// 检查组属性
				List<Map<String, Object>> results = internalQuery(group, groupName, null, null);

				for (Map<String, Object> result : results) {
					for (Map<String, Object> a : answer) {
						String uid = (String) a.get(search.getUid());

						if (findMemberUid(result, uid)) {
							// If account is existing in group
							return answer;
						}
					}
				}

				// If not in group, return null
				return null;
			}
		}

		return answer;
	}

	private Map<String, Object> getAttributes(SearchResult sr) throws NamingException {
		Attributes Attrs = sr.getAttributes();

		Map<String, Object> attrMap = null;
		if (Attrs != null) {
			// 得到每一个属性
			NamingEnumeration<?> ne = Attrs.getAll();
			while (ne.hasMore()) {
				Attribute Attr = (Attribute) ne.next();
				String attrName = Attr.getID();
				Object value = null;

				Enumeration<?> values = Attr.getAll();
				if (values != null) {
					// 得到所有属性值
					while (values.hasMoreElements()) {
						if (null != value) {
							// 如果不止一个属性值
							if (!(value instanceof List)) {
								List<Object> tempValue = new ArrayList<Object>();
								tempValue.add(value);
								value = tempValue;
							}
						}

						Object object = values.nextElement();
						if (value instanceof List) {
							((List<Object>) value).add(object);
						}
						else {
							value = object;
						}
					}
				}

				if (null == attrMap)
					attrMap = new HashMap<String, Object>();
				attrMap.put(attrName, value);
			}
		}

		return attrMap;
	}

	private boolean findMemberUid(Map<String, Object> sr, String member) throws NamingException {
		Iterator<Entry<String, Object>> entries = sr.entrySet().iterator();
		while (entries.hasNext()) {
			Entry<String, Object> entry = entries.next();
			String name = entry.getKey();
			if (name.equals(GROUP_MEMBER_QUALIFIER)) {
				if (isMember(entry.getValue(), member))
					return true;
			}
		}

		return false;
	}

	private boolean isMember(Object Attr, String member) throws NamingException {
		String value = null;
		if (Attr instanceof List) {
			List<Object> values = (List<Object>) Attr;
			for (Object object : values) {
				if (object instanceof byte[])
					value = new String((byte[]) object);
				else
					value = (String) object;
				if (value.equals(member))
					return true;
			}
		}
		else {
			Object object = (List<Object>) Attr;
			if (object instanceof byte[])
				value = new String((byte[]) object);
			else
				value = (String) object;
			if (value.equals(member))
				return true;
		}

		return false;
	}

	public void close() {
		try {
			ldapCtx.close();
		}
		catch (NamingException e) {
			logger.warn(e.getMessage(), e);
		}
	}

}
