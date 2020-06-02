package com.duminda.security.oauthbearer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.common.utils.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import static com.duminda.security.util.PropertyResolver.getPropertyValueByKey;

public class OauthHttpCalls {

    private static final Logger log = LoggerFactory.getLogger(OauthHttpCalls.class);

    private static Time time = Time.SYSTEM;

    public static void acceptUnsecureServer(){

        if(getPropertyValueByKey("OAUTH_ACCEPT_UNSECURE_SERVER").equals(true)){
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                    }
            };
            try{
                SSLContext sc = SSLContext.getInstance("SSL");
                sc.init(null, trustAllCerts, new java.security.SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            }catch(NoSuchAlgorithmException e){
                log.error("at acceptUnsecureServer :", e);
            }catch(KeyManagementException e){
                log.error("at acceptUnsecureServer :", e);
            }
        }
    }

    public static OauthBearerTokenJwt login(String clientId) {

        getPropertyValueByKey("OAUTH_LOGIN_GRANT_TYPE");
        OauthBearerTokenJwt result = null;
        try {
            acceptUnsecureServer();
            long callTime = time.milliseconds();

            //Mount POST data
            String grantType = "grant_type=" + getPropertyValueByKey("OAUTH_LOGIN_GRANT_TYPE");
            String scope = "scope=" + getPropertyValueByKey("OAUTH_LOGIN_SCOPE");
            String username = "username="+ getPropertyValueByKey("USER");
            String password = "password="+ getPropertyValueByKey("PASS");
            String postDataStr = username+ "&" + password+ "&" + grantType + "&" + scope;

            log.info("Try to login with oauth!");
            Map<String, Object> resp = null;
            if(getPropertyValueByKey("OAUTH_WITH_SSL").equals(true)){
                resp = doHttpsCall(getPropertyValueByKey("OAUTH_LOGIN_SERVER") +
                        getPropertyValueByKey("OAUTH_LOGIN_ENDPOINT"), postDataStr,
                        getPropertyValueByKey("OAUTH_LOGIN_AUTHORIZATION"));
            }else{
                resp = doHttpCall(getPropertyValueByKey("OAUTH_LOGIN_SERVER") +
                        getPropertyValueByKey("OAUTH_LOGIN_ENDPOINT"), postDataStr,
                        getPropertyValueByKey("OAUTH_LOGIN_AUTHORIZATION"));
            }

            if(resp != null){
                String accessToken = (String) resp.get("access_token");
                String refreshToken = (String) resp.get("refresh_token");
                long expiresIn = ((Integer) resp.get("expires_in")).longValue();
                result = new OauthBearerTokenJwt(accessToken, refreshToken, expiresIn, callTime, clientId);
            } else {
                throw new Exception("with resp null at login");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static OauthBearerTokenJwt introspectBearer(String accessToken){
        OauthBearerTokenJwt result = null;
        try {
            String token = "token=" +  accessToken;

            Map<String, Object> resp = null;
            if(getPropertyValueByKey("OAUTH_WITH_SSL").equals(true)){
                resp = doHttpsCall(getPropertyValueByKey("OAUTH_INTROSPECT_SERVER") +
                        getPropertyValueByKey("OAUTH_INTROSPECT_ENDPOINT"), token,
                        getPropertyValueByKey("OAUTH_INTROSPECT_AUTHORIZATION"));
            }else{
                resp = doHttpCall(getPropertyValueByKey("OAUTH_INTROSPECT_SERVER") +
                        getPropertyValueByKey("OAUTH_INTROSPECT_ENDPOINT"), token,
                        getPropertyValueByKey("OAUTH_INTROSPECT_AUTHORIZATION"));

            }
            if(resp != null){
                if((boolean) resp.get("active")){
                    log.info("====active====");
                    result = new OauthBearerTokenJwt(resp, accessToken);
                }else{
                    log.info("====expired====");

                    throw new Exception("Expired Token");
                }
            }
        }catch (Exception e){
            log.info("====exception(introspectBearer)====");
            e.printStackTrace();
        }
        return result;
    }

    private static Map<String, Object> doHttpCall(String urlStr, String postParameters, String oauthToken){
        try{
            //System.out.println("doHttpCall ->" + urlStr + " , postParameters="+ postParameters+ " ,oauthToken=" + oauthToken);
            //log.info("doHttpCall ---->" + urlStr + " , postParameters="+ postParameters+ " ,oauthToken=" + oauthToken + "<------");
            acceptUnsecureServer();

            byte[] postData = postParameters.getBytes( StandardCharsets.UTF_8 );
            int postDataLength = postData.length;

            URL url = new URL("http://" + urlStr);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setInstanceFollowRedirects(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Authorization", oauthToken);
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            con.setRequestProperty("charset", "utf-8");
            con.setRequestProperty("Content-Length", Integer.toString(postDataLength ));
            con.setUseCaches(false);
            con.setDoOutput(true);

            try(DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                wr.write( postData );
            }

            int responseCode = con.getResponseCode();
            if (responseCode == 200) {
                return handleJsonResponse(con.getInputStream());
            } else {
                throw new Exception("Return code " + responseCode);
            }
        }catch (Exception e){
            log.error("at doHttpCall", e);
        }
        return null;
    }

    private static Map<String, Object> doHttpsCall(String urlStr, String postParameters, String oauthToken){
        try{

            acceptUnsecureServer();

            byte[] postData = postParameters.getBytes( StandardCharsets.UTF_8 );
            int postDataLength = postData.length;

            URL url = new URL("https://" + urlStr);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
            con.setInstanceFollowRedirects(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Authorization", oauthToken);
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            con.setRequestProperty("charset", "utf-8");
            con.setRequestProperty("Content-Length", Integer.toString(postDataLength ));
            con.setUseCaches(false);
            con.setDoOutput(true);

            try(DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                wr.write( postData );
            }

            int responseCode = con.getResponseCode();
            if (responseCode == 200) {
                return handleJsonResponse(con.getInputStream());
            }else {
                throw new Exception("Return code " + responseCode);
            }
        }catch (Exception e){
            log.error("at doHttpCall");
        }
        return null;
    }


    private static Map<String,Object> handleJsonResponse(InputStream inputStream){
        Map<String, Object> result = null;
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(inputStream));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            String jsonResponse = response.toString();
            ObjectMapper objectMapper = new ObjectMapper();
            result = objectMapper.readValue(jsonResponse, new TypeReference<Map<String,Object>>(){});

        }catch (Exception e){
            e.printStackTrace();
        }
        return result;
    }
}
