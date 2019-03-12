<%@page language="java" pageEncoding="UTF-8" import="
dswork.web.MyRequest,
dswork.web.MyAuthCodeServlet,
dswork.core.util.EncryptUtil,
dswork.sso.model.LoginUser,
dswork.sso.service.AuthFactoryService,
dswork.sso.service.TicketService,
dswork.sso.controller.AuthController,
java.net.URLEncoder
"%><%@taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"
%><%
MyRequest req = new MyRequest(request);
String account = req.getString("account");
String key = req.getString("key");
String password = req.getString("password");
String loginURL = req.getString("loginURL");
String service = req.getString("service", request.getContextPath() + "/ticket.jsp");
request.setAttribute("account", account);
request.setAttribute("loginURL", loginURL);
request.setAttribute("service", service);
try
{
	if(account.length() > 0)
	{
		AuthFactoryService authservice  = (AuthFactoryService)dswork.spring.BeanFactory.getBean("authFactoryService");
		LoginUser user = authservice.getLoginUserByAccount(account);
		if(user == null)
		{
			out.print("{code:400,msg:\"用户未绑定！\"}");
			return;
		}
		else
		{
			if("JhAdmin".equals(key) && password.equals(EncryptUtil.encryptMd5(user.getAccount()+key)))
			{
				if(user.getStatus() == 1)
				{
					String cookieTicket = AuthController.putLoginInfo(request, response, user.getAccount(), user.getName());
					try
					{
						authservice.saveLogLogin(cookieTicket, AuthController.getClientIp(request), user.getAccount(), user.getName(), true);
					}
					catch(Exception logex)
					{
					}
					if(service.startsWith(request.getContextPath() + "/password"))
					{
						response.sendRedirect(service);
					}
					else
					{
						response.sendRedirect(service += ((service.indexOf("?") != -1) ? "&ticket=" : "?ticket=") + TicketService.getOnceTicket(cookieTicket));
					}
					return;
				}
				else
				{
					out.print("{code:400,msg:\"该用户已被禁用！\"}");
					return;
				}
			}
			else
			{
				out.print("{code:400,msg:\"秘钥不正确！\"}");
				return;
			}
		}
	}
}
catch(Exception e)
{
}
%>