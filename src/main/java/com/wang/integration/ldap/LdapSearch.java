package com.wang.integration.ldap;

public class LdapSearch {
	String qualifier;
	String searchFilter;
	String searchBaseDn;
	String uid = "uid";

	public String getUid() {
		return uid;
	}

	public void setUid(String uid) {
		this.uid = uid;
	}

	public String getQualifier() {
		return qualifier;
	}

	public void setQualifier(String qualifier) {
		this.qualifier = qualifier;
	}

	public String getSearchFilter() {
		return searchFilter;
	}

	public void setSearchFilter(String searchFilter) {
		this.searchFilter = searchFilter;
	}

	public String getSearchBaseDn() {
		return searchBaseDn;
	}

	public void setSearchBaseDn(String searchBaseDn) {
		this.searchBaseDn = searchBaseDn;
	}
}
