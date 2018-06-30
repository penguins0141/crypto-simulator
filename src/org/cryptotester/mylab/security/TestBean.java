package org.cryptotester.mylab.security;

import java.sql.Date;

public class TestBean {
	
	private String beanName = "";
	public TestBean(String beanName, String beanLocation, String beanAction,
			Date beanDate, int beanNumber) {
		super();
		this.beanName = beanName;
		this.beanLocation = beanLocation;
		this.beanAction = beanAction;
		this.beanDate = beanDate;
		this.beanNumber = beanNumber;
	}

	public String getBeanName() {
		return beanName;
	}

	public void setBeanName(String beanName) {
		this.beanName = beanName;
	}

	public String getBeanLocation() {
		return beanLocation;
	}

	public void setBeanLocation(String beanLocation) {
		this.beanLocation = beanLocation;
	}

	public String getBeanAction() {
		return beanAction;
	}

	public void setBeanAction(String beanAction) {
		this.beanAction = beanAction;
	}

	public Date getBeanDate() {
		return beanDate;
	}

	public void setBeanDate(Date beanDate) {
		this.beanDate = beanDate;
	}

	public int getBeanNumber() {
		return beanNumber;
	}

	public void setBeanNumber(int beanNumber) {
		this.beanNumber = beanNumber;
	}

	private String beanLocation = "";
	private String beanAction = "";
	private Date beanDate = null;
	private int beanNumber = 1;

	public TestBean() {
		// TODO Auto-generated constructor stub
	}

}
