package burp;

import org.json.JSONException;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import static java.util.Arrays.asList;

public class BurpExtender implements IBurpExtender, IScannerCheck {
	private PrintWriter stdout;
	private static final String EXTENSION_NAME = "path_scan";
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	String json_path="/Users/chenguang/Desktop/burp/插件/path_scan/src/burp/test.json";

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		callbacks.setExtensionName(EXTENSION_NAME);
		callbacks.registerScannerCheck(this);
		stdout = new PrintWriter(callbacks.getStdout(), true);
	}
	List urllist = new ArrayList<>();



	private ExecutorService executorService;
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {


		executorService = Executors.newFixedThreadPool(10);
		executorService.execute(()-> {
			URL request_url = helpers.analyzeRequest(baseRequestResponse).getUrl();
			if (!callbacks.isInScope(request_url)) {
				return;
			}
			if (urllist.contains(request_url)) {
				return;
			}
			IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
			List<String> list = asList("myqcloud.com", ".3g2", ".3gp", ".7z", ".aac", ".abw", ".aif", ".aifc", ".aiff", ".arc", ".au", ".avi", ".azw", ".bin", ".bmp", ".bz", ".bz2", ".cmx", ".cod", ".csh", ".css", ".csv", ".doc", ".docx", ".eot", ".epub", ".gif", ".gz", ".ico", ".ics", ".ief", ".jar", ".jfif", ".jpe", ".jpeg", ".jpg", ".m3u", ".mid", ".midi", ".mjs", ".mp2", ".mp3", ".mpa", ".mpe", ".mpeg", ".mpg", ".mpkg", ".mpp", ".mpv2", ".odp", ".ods", ".odt", ".oga", ".ogv", ".ogx", ".otf", ".pbm", ".pdf", ".pgm", ".png", ".pnm", ".ppm", ".ppt", ".pptx", ".ra", ".ram", ".rar", ".ras", ".rgb", ".rmi", ".rtf", ".snd", ".svg", ".swf", ".tar", ".tif", ".tiff", ".ttf", ".vsd", ".wav", ".weba", ".webm", ".webp", ".woff", ".woff2", ".xbm", ".xls", ".xlsx", ".xpm", ".xul", ".xwd", ".zip", ".zip", ".js");
			for (int i = 0; i < list.size(); i++) {
				String type = list.get(i);
				if (request_url.toString().contains(type)) {
					return;
				}
			}

			List<String> newRequestHeaders = new ArrayList<>();
			List<String> requestHeaders = requestInfo.getHeaders();
			for (String header : requestHeaders) {
				if (header.toLowerCase().startsWith("user-agent") | header.contains("HTTP/") | header.toLowerCase().startsWith("host")) {
					newRequestHeaders.add(header);
				}
			}
			String full_path = "";
			String path = request_url.getPath();
			String[] pathSegments = path.split("/");
			String baseUrl = request_url.getProtocol() + "://" + request_url.getHost();
			for (int i = 0; i < pathSegments.length; i++) {
				try (BufferedReader reader = new BufferedReader(new FileReader(json_path))) {
					stdout.println(json_path);
					StringBuilder jsonContent = new StringBuilder();
					String line;
					while ((line = reader.readLine()) != null) {
						jsonContent.append(line);
					}
					String json = jsonContent.toString();
					stdout.println(json);
					JSONObject jsonObject = new JSONObject(json);
					Iterator<String> keys = jsonObject.keys();
					stdout.println(keys);
					while (keys.hasNext()) {
						String scan_path = keys.next();
						Object test_str = jsonObject.get(scan_path);

						String full_path2 = full_path  +"/"+ pathSegments[i];
						baseUrl = baseUrl + "/" + pathSegments[i];
						if(pathSegments[i].matches("\\d+")){
							continue;
						}
						scan_path = (full_path2+"/"+scan_path).replace("//","/");
						if (urllist.contains(baseUrl)){
							continue;
						}
						urllist.add(baseUrl);
						byte[] newRequestBytes = callbacks.getHelpers().buildHttpMessage(newRequestHeaders, null);
						String newRequestString = callbacks.getHelpers().bytesToString(newRequestBytes);
						newRequestString = newRequestString.replaceFirst(path, scan_path).replaceFirst(requestInfo.getMethod(),"GET");
						newRequestBytes = callbacks.getHelpers().stringToBytes(newRequestString);
						IHttpRequestResponse newRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequestBytes);
						String response = callbacks.getHelpers().bytesToString(newRequestResponse.getResponse());
						if (response.contains((String)test_str)) {
							callbacks.addScanIssue(new CustomScanIssue(
									baseRequestResponse.getHttpService(),
									helpers.analyzeRequest(baseRequestResponse).getUrl(),
									new IHttpRequestResponse[]{callbacks.applyMarkers(newRequestResponse, null, null)},
									"FIND actuator",
									"actuator",
									"High"));
						}

					}

				} catch (IOException | JSONException e) {
					e.printStackTrace();
				}


			}

		});
		return null;
	}    @Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
			return -1;
		} else {
			return 0;
		}
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
		return null;
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
