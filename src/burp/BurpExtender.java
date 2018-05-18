/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.util.HashSet;
import java.util.Set;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author jamesjardine
 */
public class BurpExtender implements IBurpExtender, IScannerCheck
{
    IBurpExtenderCallbacks callbacks = null;
    private IExtensionHelpers helpers;
    
    
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("Custom Scanner Checks");
        
        callbacks.registerScannerCheck(this);
    }
    
    private List<int[]> getMatches(byte[] response)
    {
        
        byte[] startString = "$routeProvider".getBytes();
        byte[] endString = "]".getBytes();
        List<int[]> matches = new ArrayList<int[]>();
        
        int start = 0;

        start = helpers.indexOf(response,startString,true,start,response.length);
        if(start > -1)
        {
            int end = 0;
            end = helpers.indexOf(response,endString,true,start+1,response.length);
            if(end > -1)
            {
                matches.add(new int[] {start,end });
            }
        }
        
        return matches;
    }
    
    private List<String> getRoutes(String data)
    {
        
        List<String> matches = new ArrayList<String>();
        String startString = ".when(";
        String endString = ",";
        
        int start = 0;
        int end = 1;
        while (start < data.length())
        {
            start = data.indexOf(startString,start);
            if(start == -1)
                break;
            end = data.indexOf(endString,start);
            matches.add(data.substring(start+8,end - 1));
            start = end;
        }
        return matches;
    }
  
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        
        List<int[]> matches = getMatches(baseRequestResponse.getResponse());
        if(matches.size() > 0)
        {
            
            IResponseInfo iri = helpers.analyzeResponse(baseRequestResponse.getResponse());
            String body = (new String(baseRequestResponse.getResponse())).substring(iri.getBodyOffset());
            List<String> indMatch = getRoutes(body);
            String listString = "<ul>";
            for(String s : indMatch)
            {
                listString += "<li>" + s + "</li>";
            }
            listString += "</ul>";
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{ callbacks.applyMarkers(baseRequestResponse,null,matches)},
            "Angular Routes",
            "The Response containst the string: routeProvider and has the following Routes \n" + listString,
            "Information"));
            return issues;
        }
        else return null;
    }
    
        @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }
    
        @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
}

class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
}
