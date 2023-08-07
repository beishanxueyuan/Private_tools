package burp;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.URL;
import java.util.List;
import static java.util.Arrays.asList;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IScannerCheck {
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;


        public static byte[] strToByteArray(String str) {
            if (str == null) {
                return null;
            }
            byte[] byteArray = str.getBytes();
            return byteArray;
        }


    public static boolean isNumericZidai(String str) {
        for (int i = 0; i < str.length(); i++) {
            if (!Character.isDigit(str.charAt(i))) {
                return false;
            }
        }
        return true;
    }



    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("fucksql");
        callbacks.registerScannerCheck(this);
    }
    private ExecutorService executorService;

    @Override

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        executorService = Executors.newFixedThreadPool(2);
        executorService.execute(()-> {
            byte[] new_Request = new byte[0];
            byte[] new_Request2 = new byte[0];

            byte[] request = baseRequestResponse.getRequest();
            byte[] response = baseRequestResponse.getResponse();
//过滤垃圾数据包
            URL request_url = helpers.analyzeRequest(baseRequestResponse).getUrl();
            List<String> list = asList("myqcloud.com", ".3g2", ".3gp", ".7z", ".aac", ".abw", ".aif", ".aifc", ".aiff", ".arc", ".au", ".avi", ".azw", ".bin", ".bmp", ".bz", ".bz2", ".cmx", ".cod", ".csh", ".css", ".csv", ".doc", ".docx", ".eot", ".epub", ".gif", ".gz", ".ico", ".ics", ".ief", ".jar", ".jfif", ".jpe", ".jpeg", ".jpg", ".m3u", ".mid", ".midi", ".mp4", ".mjs", ".mp2", ".mp3", ".mpa", ".mpe", ".mpeg", ".mpg", ".mpkg", ".mpp", ".mpv2", ".odp", ".ods", ".odt", ".oga", ".ogv", ".ogx", ".otf", ".pbm", ".pdf", ".pgm", ".png", ".pnm", ".ppm", ".ppt", ".pptx", ".ra", ".ram", ".rar", ".ras", ".rgb", ".rmi", ".rtf", ".snd", ".svg", ".swf", ".tar", ".tif", ".tiff", ".ttf", ".vsd", ".wav", ".weba", ".webm", ".webp", ".woff", ".woff2", ".xbm", ".xls", ".xlsx", ".xpm", ".xul", ".xwd", ".zip", ".zip", ".js");
            List<String> req_header_list = asList("application/octet-stream");
            for (String header : helpers.analyzeRequest(request).getHeaders()) {
                for (int i = 0; i < req_header_list.size(); i++) {
                    String false_header = req_header_list.get(i);
                    if (header.contains(false_header)) {
                        return;
                    }
                }
            }
            String host = request_url.getHost();
            for (int i = 0; i < list.size(); i++) {
                String type = list.get(i);
                if (request_url.toString().contains(type) && !host.contains(type)) {
                    return;
                }
            }
            if (!callbacks.isInScope(request_url)) {
                return;
            }

            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            IRequestInfo analyzedRequest = helpers.analyzeRequest(request);

                String origin_response = new String(baseRequestResponse.getResponse());
                String origin_request = new String(baseRequestResponse.getRequest());
                int bodyOffset = responseInfo.getBodyOffset();
                int request_bodyOffset = analyzedRequest.getBodyOffset();
                String request_body = origin_request.substring(request_bodyOffset);
                String body = origin_response.substring(bodyOffset);
                List<IParameter> paraList = analyzedRequest.getParameters();

                for (IParameter para : paraList) {
                    if (!callbacks.isInScope(request_url)) {
                        return;
                    }
                    if(!request_body.matches(".*?([\\w\\W]+)=(\\s|.*?)") & para.getType() == 1){
                        return;
                    }
                    String key = para.getName();
                    int type = para.getType();
//post or get request
                    if (type == 0 || type == 1) {
                        boolean is_not_null = para.getValue().matches(".*[A-Za-z0-9]+.*");
                        String value;
                        if(is_not_null){
                            value=para.getValue();
                        }
                        else {
                            value="1";
                        }
//int injection
                        if (isNumericZidai(para.getValue())) {
                            IParameter newPara = helpers.buildParameter(key, value + "-a", para.getType());
                            new_Request = baseRequestResponse.getRequest();
                            new_Request = helpers.updateParameter(new_Request, newPara);
                            IHttpRequestResponse req = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                            IResponseInfo analyzedResponse1 = helpers.analyzeResponse(req.getResponse());
                            int int_bodyOffset1 = analyzedResponse1.getBodyOffset();
                            String int_body1 = new String(req.getResponse()).substring(int_bodyOffset1);
                            StringSimilarity similar = new StringSimilarity();
                            double similarity = similar.lengthRatio(body,int_body1);
                            if(similarity>0.05) {
                                newPara = helpers.buildParameter(key, value + "-0", para.getType());
                                new_Request = baseRequestResponse.getRequest();
                                new_Request = helpers.updateParameter(new_Request, newPara);
                                IHttpRequestResponse req2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                                IResponseInfo analyzedResponse2 = helpers.analyzeResponse(req2.getResponse());
                                int int_bodyOffset2 = analyzedResponse2.getBodyOffset();
                                String int_body2 = new String(req2.getResponse()).substring(int_bodyOffset2);
                                double similarity1 = similar.lengthRatio(int_body1, int_body2);
                                if (similarity1 > 0.05) {
                                    callbacks.addScanIssue(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[]{callbacks.applyMarkers(req, null, null), callbacks.applyMarkers(req2, null, null)},
                                            "SQL TEST",
                                            "Key: " + key + "\nSimilarity: " + similarity + "%",
                                            "High"));
                                }
                            }
                        }
//str injection
                        IParameter newPara = helpers.buildParameter(key, value + "'", para.getType());
                        new_Request = baseRequestResponse.getRequest();
                        new_Request = helpers.updateParameter(new_Request, newPara);
                        IHttpRequestResponse req = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                        IResponseInfo analyzedResponse1 = helpers.analyzeResponse(req.getResponse());
                        int int_bodyOffset1 = analyzedResponse1.getBodyOffset();
                        String int_body1 = new String(req.getResponse()).substring(int_bodyOffset1);
                        StringSimilarity similar = new StringSimilarity();
                        double similarity = similar.lengthRatio(body,int_body1);
                        if(similarity > 0.05) {
                            newPara = helpers.buildParameter(key, value + "''", para.getType());
                            new_Request = baseRequestResponse.getRequest();
                            new_Request = helpers.updateParameter(new_Request, newPara);
                            IHttpRequestResponse req2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                            IResponseInfo analyzedResponse2 = helpers.analyzeResponse(req2.getResponse());
                            int int_bodyOffset2 = analyzedResponse2.getBodyOffset();
                            String int_body2 = new String(req2.getResponse()).substring(int_bodyOffset2);
                            double similarity1 = similar.lengthRatio(int_body1, int_body2);
                            if (similarity1 > 0.05) {
                                callbacks.addScanIssue(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[]{callbacks.applyMarkers(req, null, null), callbacks.applyMarkers(req2, null, null)},
                                        "SQL TEST",
                                        "Key: " + key + "\nSimilarity: " + similarity1 + "%",
                                        "High"));
                            }
                        }
//order by
                        IParameter newPara_orderby = helpers.buildParameter(key, value + ",aaaa", para.getType());
                        new_Request = baseRequestResponse.getRequest();
                        new_Request = helpers.updateParameter(new_Request, newPara_orderby);
                        IHttpRequestResponse req_orderby1 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                        IResponseInfo analyzedResponse_orderby1 = helpers.analyzeResponse(req_orderby1.getResponse());
                        int int_bodyOffset_orderby1 = analyzedResponse_orderby1.getBodyOffset();
                        String int_body_orderby1 = new String(req_orderby1.getResponse()).substring(int_bodyOffset_orderby1);
                        StringSimilarity similar_orderby1 = new StringSimilarity();
                        double similarity_orderby1 = similar_orderby1.lengthRatio(body,int_body_orderby1);
                        if(similarity_orderby1 > 0.05) {
                            newPara_orderby = helpers.buildParameter(key, value + ",true", para.getType());
                            new_Request = baseRequestResponse.getRequest();
                            new_Request = helpers.updateParameter(new_Request, newPara_orderby);
                            IHttpRequestResponse req_orderby2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                            IResponseInfo analyzedResponse2 = helpers.analyzeResponse(req_orderby2.getResponse());
                            int int_bodyOffset2 = analyzedResponse2.getBodyOffset();
                            String int_body2 = new String(req_orderby2.getResponse()).substring(int_bodyOffset2);
                            double similarity1 = similar.lengthRatio(int_body_orderby1, int_body2);
                            if (similarity1 > 0.05) {
                                callbacks.addScanIssue(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new IHttpRequestResponse[]{callbacks.applyMarkers(req_orderby1, null, null), callbacks.applyMarkers(req_orderby2, null, null)},
                                        "SQL TEST",
                                        "Key: " + key + "\nSimilarity: " + similarity1 + "%",
                                        "High"));
                            }
                        }
                    }
                }

//json request
                List request_headers = analyzedRequest.getHeaders();
                if (request_body.contains("\":\"") || request_body.contains("\":[\"")) {
//json list
                    if (request_body.contains(":[")) {
                        Pattern p_list = Pattern.compile("(\"|\\\\\")(\\w+)(\"|\\\\\"):\\[(.*?)\\]");
                        Matcher m_list = p_list.matcher(request_body);
                        String json_list = null;
                        String json_key = null;
                        String e_str = null;
                        String[] list_values = new String[0];
                        while (m_list.find()) {
                            if (!callbacks.isInScope(request_url)) {
                                return;
                            }
                            json_key = m_list.group(2);
                            json_list = m_list.group();
                            list_values = m_list.group(4).split(",");
                            e_str = m_list.group(3);
                        }
                        boolean is_not_null = json_list.matches(".*[A-Za-z0-9]+.*");
                        if (!is_not_null) {
                            return;
                        }

                        String new_para1 = "";
                        String new_para2 = "";
                        for (String list_value : list_values) {
                            if (!callbacks.isInScope(request_url)) {
                                return;
                            }
                            String real_list_value=list_value;
                            if (list_value.equals(e_str+e_str)){
                                list_value=e_str+"1"+e_str;
                            }
                            String  json_value = list_value.replace(e_str, "");
                            if (isNumericZidai(json_value)) {
                                new_para1 = json_list.replace(real_list_value,list_value.replace(json_value, json_value + "-a"));//
                                new_para2 = json_list.replace(real_list_value, list_value.replace(json_value, json_value + "-a"));
                                String s_new_request_body1 = request_body.replace(json_list, new_para1);
                                byte[] b_new_request_body1 = strToByteArray(s_new_request_body1);
                                new_Request = helpers.buildHttpMessage(request_headers, b_new_request_body1);
                                IHttpRequestResponse req = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                                IResponseInfo analyzedResponse1 = helpers.analyzeResponse(req.getResponse());
                                int int_bodyOffset1 = analyzedResponse1.getBodyOffset();
                                String int_body1 = new String(req.getResponse()).substring(int_bodyOffset1);
                                StringSimilarity similar = new StringSimilarity();
                                double similarity = similar.lengthRatio(body, int_body1);
                                if (similarity > 0.05) {
                                    String s_new_request_body2 = request_body.replace(json_list, new_para2);
                                    byte[] b_new_request_body2 = strToByteArray(s_new_request_body2);
                                    new_Request = helpers.buildHttpMessage(request_headers, b_new_request_body2);
                                    IHttpRequestResponse req2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                                    IResponseInfo analyzedResponse2 = helpers.analyzeResponse(req2.getResponse());
                                    int int_bodyOffset2 = analyzedResponse2.getBodyOffset();
                                    String int_body2 = new String(req2.getResponse()).substring(int_bodyOffset2);
                                    double similarity2 = similar.lengthRatio(int_body1, int_body2);
                                    if (similarity2 > 0.05) {
                                        callbacks.addScanIssue(new CustomScanIssue(
                                                baseRequestResponse.getHttpService(),
                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                new IHttpRequestResponse[]{callbacks.applyMarkers(req, null, null), callbacks.applyMarkers(req2, null, null)},
                                                "SQL TEST",
                                                "Key: " + json_key + "\nSimilarity: " + similarity2 + "%",
                                                "High"));

                                    }

                                }
                            }
                            new_para1 = json_list.replace(real_list_value,list_value.replace(json_value, json_value + "'"));
                            new_para2 = json_list.replace(real_list_value,list_value.replace(json_value, json_value + "''"));
                            String s_new_request_body1 = request_body.replace(json_list, new_para1);
                            byte[] b_new_request_body1 = strToByteArray(s_new_request_body1);
                            new_Request = helpers.buildHttpMessage(request_headers, b_new_request_body1);
                            IHttpRequestResponse req = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                            IResponseInfo analyzedResponse1 = helpers.analyzeResponse(req.getResponse());
                            int int_bodyOffset1 = analyzedResponse1.getBodyOffset();
                            String int_body1 = new String(req.getResponse()).substring(int_bodyOffset1);
                            StringSimilarity similar = new StringSimilarity();
                            double similarity = similar.lengthRatio(body, int_body1);
                            if (similarity > 0.05) {
                                String s_new_request_body2 = request_body.replace(json_list, new_para2);
                                byte[] b_new_request_body2 = strToByteArray(s_new_request_body2);
                                new_Request = helpers.buildHttpMessage(request_headers, b_new_request_body2);
                                IHttpRequestResponse req2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                                IResponseInfo analyzedResponse2 = helpers.analyzeResponse(req2.getResponse());
                                int int_bodyOffset2 = analyzedResponse2.getBodyOffset();
                                String int_body2 = new String(req2.getResponse()).substring(int_bodyOffset2);
                                double similarity2 = similar.lengthRatio(int_body1, int_body2);
                                if (similarity2 > 0.05) {
                                    callbacks.addScanIssue(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[]{callbacks.applyMarkers(req, null, null), callbacks.applyMarkers(req2, null, null)},
                                            "SQL TEST",
                                            "Key: " + json_key + "\nSimilarity: " + similarity2 + "%",
                                            "High"));

                                }

                            }
                        }

                    }


//json
                    String pattern = "(\"|\\\\\")(\\w+)(\"|\\\\\"):(\"|\\\\\")(.*?)(\"|\\\\\")";
                    Pattern r = Pattern.compile(pattern);
                    Matcher m = r.matcher(request_body);
                    while (m.find()) {
                        if (!callbacks.isInScope(request_url)) {
                            return;
                        }
                        String json_real_key = m.group(2);
                        String json_key = m.group(2) + m.group(3);
                        String json_real_value = m.group(5);
                        String json_value = m.group(4) + m.group(5);
                        if ((json_value.startsWith("\"") || json_value.startsWith("\\\"")) && !json_value.contains("{")) {
                            String old_para = json_key + ":" + json_value;
                            String new_para = "";
                            String new_para1 = "";
                            String new_para2 = "";
                            String new_para_orderby_1 = "";
                            String new_para_orderby_2 = "";
                            if (json_value.endsWith("\"")) {
                                json_value = json_value + "1";
                                json_real_value = "1";
                            }
                            if (isNumericZidai(json_real_value)) {
                                new_para1 = json_key + ":" + json_value + "-a";
                                new_para2 = json_key + ":" + json_value + "-0";
                                String s_new_request_body1 = request_body.replace(old_para,new_para1);
                                byte[] b_new_request_body1 = strToByteArray(s_new_request_body1);
                                new_Request = helpers.buildHttpMessage(request_headers, b_new_request_body1);
                                IHttpRequestResponse req = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                                IResponseInfo analyzedResponse1 = helpers.analyzeResponse(req.getResponse());
                                int int_bodyOffset1 = analyzedResponse1.getBodyOffset();
                                String int_body1 = new String(req.getResponse()).substring(int_bodyOffset1);
                                StringSimilarity similar = new StringSimilarity();
                                double similarity = similar.lengthRatio(body,int_body1);
                                if (similarity>0.05){
                                    String s_new_request_body2 = request_body.replace(old_para,new_para2);
                                    byte[] b_new_request_body2 = strToByteArray(s_new_request_body2);
                                    new_Request = helpers.buildHttpMessage(request_headers, b_new_request_body2);
                                    IHttpRequestResponse req2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                                    IResponseInfo analyzedResponse2 = helpers.analyzeResponse(req2.getResponse());
                                    int int_bodyOffset2 = analyzedResponse2.getBodyOffset();
                                    String int_body2 = new String(req2.getResponse()).substring(int_bodyOffset2);
                                    double similarity2 = similar.lengthRatio(int_body1,int_body2);
                                    if (similarity2>0.05){
                                        callbacks.addScanIssue(new CustomScanIssue(
                                                baseRequestResponse.getHttpService(),
                                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                new IHttpRequestResponse[]{callbacks.applyMarkers(req, null, null), callbacks.applyMarkers(req2, null, null)},
                                                "SQL TEST",
                                                "Key: " + json_real_key + "\nSimilarity: " + similarity2 + "%",
                                                "High"));

                                    }

                                }

                            }

                            new_para1 = json_key + ":" + json_value + "'";
                            new_para2 = json_key + ":" + json_value + "''";
                            String s_new_request_body1 = request_body.replace(old_para,new_para1);
                            byte[] b_new_request_body1 = strToByteArray(s_new_request_body1);
                            new_Request = helpers.buildHttpMessage(request_headers, b_new_request_body1);
                            IHttpRequestResponse req = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                            IResponseInfo analyzedResponse1 = helpers.analyzeResponse(req.getResponse());
                            int int_bodyOffset1 = analyzedResponse1.getBodyOffset();
                            String int_body1 = new String(req.getResponse()).substring(int_bodyOffset1);
                            StringSimilarity similar = new StringSimilarity();
                            double similarity = similar.lengthRatio(body,int_body1);
                            if (similarity>0.05){
                                String s_new_request_body2 = request_body.replace(old_para,new_para2);
                                byte[] b_new_request_body2 = strToByteArray(s_new_request_body2);
                                new_Request = helpers.buildHttpMessage(request_headers, b_new_request_body2);
                                IHttpRequestResponse req2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                                IResponseInfo analyzedResponse2 = helpers.analyzeResponse(req2.getResponse());
                                int int_bodyOffset2 = analyzedResponse2.getBodyOffset();
                                String int_body2 = new String(req2.getResponse()).substring(int_bodyOffset2);
                                double similarity2 = similar.lengthRatio(int_body1,int_body2);
                                if (similarity2>0.05){
                                    callbacks.addScanIssue(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[]{callbacks.applyMarkers(req, null, null), callbacks.applyMarkers(req2, null, null)},
                                            "SQL TEST",
                                            "Key: " + json_real_key + "\nSimilarity: " + similarity2 + "%",
                                            "High"));

                                }

                            }

                            new_para_orderby_1 = json_key + ":" + json_value + ",aaaa";
                            new_para_orderby_2 = json_key + ":" + json_value + ",true";
                            String s_new_request_body_orderby_1 = request_body.replace(old_para,new_para_orderby_1);
                            byte[] b_new_request_body_orderby_1 = strToByteArray(s_new_request_body_orderby_1);
                            new_Request = helpers.buildHttpMessage(request_headers, b_new_request_body_orderby_1);
                            IHttpRequestResponse req_orderby_1 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                            IResponseInfo analyzedResponse_orderby_1 = helpers.analyzeResponse(req_orderby_1.getResponse());
                            int int_bodyOffset_orderby_1 = analyzedResponse_orderby_1.getBodyOffset();
                            String int_body_orderby_1 = new String(req_orderby_1.getResponse()).substring(int_bodyOffset_orderby_1);
                            similarity = similar.lengthRatio(body,int_body_orderby_1);
                            if (similarity>0.05){
                                String s_new_request_body2 = request_body.replace(old_para,new_para_orderby_2);
                                byte[] b_new_request_body2 = strToByteArray(s_new_request_body2);
                                new_Request = helpers.buildHttpMessage(request_headers, b_new_request_body2);
                                IHttpRequestResponse req2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_Request);
                                IResponseInfo analyzedResponse2 = helpers.analyzeResponse(req2.getResponse());
                                int int_bodyOffset2 = analyzedResponse2.getBodyOffset();
                                String int_body2 = new String(req2.getResponse()).substring(int_bodyOffset2);
                                double similarity2 = similar.lengthRatio(int_body_orderby_1,int_body2);
                                if (similarity2>0.05){
                                    callbacks.addScanIssue(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            new IHttpRequestResponse[]{callbacks.applyMarkers(req_orderby_1, null, null), callbacks.applyMarkers(req2, null, null)},
                                            "SQL TEST",
                                            "Key: " + json_real_key + "\nSimilarity: " + similarity2 + "%",
                                            "High"));

                                }

                            }
                        }
                    }
                }
        });
        return null;
    }


    @Override
    public List<IScanIssue> doActiveScan (IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint
            insertionPoint){
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()) && existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
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
