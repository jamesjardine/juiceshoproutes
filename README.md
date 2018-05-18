# juiceshoproutes
Simple Burp plugin to identify routes in the OWASP Juice Shop App

This project is just a sample to show how a simple burp extension can be created to help identify specific information. In this case, the tool works with Angular applications that expose the RouteProvider to the client. 

This tool is very basic and I am sure there are better ways to extract this information. It works for helping identify the avialable routes in the OWASP Juice Shop vulnerable application.

## Use
The extension is easy to use, however becuase it uses the passive scanner it does require the commercial version of Burp Suite. Build the Jar file and then in Burp open up the Extender tab. Next, select the Add button and select your new JAR file. Visit the Juice Shop application and click the Target Tab in Burp. Find the Juice Shop URL in the left and select it. Then, click on the Issue tab and look for the Angular Routes issue. Viewing the description should show you the routes within the application.
