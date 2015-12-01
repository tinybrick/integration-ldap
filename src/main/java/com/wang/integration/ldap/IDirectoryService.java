package com.wang.integration.ldap;

import java.util.List;
import java.util.Map;

public interface IDirectoryService {

	public abstract List<Map<String, Object>> detail(String username) throws Exception;

	public abstract List<Map<String, Object>> detail(String username, String group) throws Exception;

	public abstract List<Map<String, Object>> getByMobile(String mobile) throws Exception;

	public abstract List<Map<String, Object>> getByMobile(String mobile, String group) throws Exception;

	public abstract boolean verifyUser(String username, String password) throws Exception;

	public abstract boolean verifyUser(String username, String password, String group) throws Exception;

	public abstract boolean inGroup(String username, String group) throws Exception;

	public abstract boolean inGroup(String username, String password, String group) throws Exception;

}