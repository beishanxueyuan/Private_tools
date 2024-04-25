package com.logger;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import static burp.api.montoya.core.ByteArray.byteArray;
import java.awt.*;
import java.nio.charset.StandardCharsets;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;

class MyExtensionProvidedHttpResponseEditor implements ExtensionProvidedHttpResponseEditor {
    private final RawEditor ResponseEditor;

    private HttpRequestResponse requestResponse;
    private final MontoyaApi api;

    MyExtensionProvidedHttpResponseEditor(MontoyaApi api, EditorCreationContext creationContext) {
        this.api = api;
        ResponseEditor = api.userInterface().createRawEditor();
    }

    

    @Override
    public String caption() {
        return "Body";
    }

    @Override
    public Component uiComponent() {
        return ResponseEditor.uiComponent();
    }
    

    @Override
    public Selection selectedData() {
        return ResponseEditor.selection().isPresent() ? ResponseEditor.selection().get() : null;
    }

    @Override
    public boolean isModified() {
        return ResponseEditor.isModified();
    }

    @Override
    public HttpResponse getResponse() {
        HttpResponse Response;
        Response = requestResponse.response();
        return Response;
    }
    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse.response().bodyToString() != null && requestResponse.response().bodyToString() != "") {
            return true;
        } else {
            return false;
        }

    }
    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        String body_str = requestResponse.response().bodyToString();
        String beautifiedJson = "";
        Logging logging = api.logging();
        ByteArray body;
        if ((body_str.contains("\":\""))) {
            ObjectMapper objectMapper = new ObjectMapper();
            ObjectWriter writer = objectMapper.writer().with(SerializationFeature.INDENT_OUTPUT);
            Object json;
            try {
                json = objectMapper.readValue(body_str, Object.class);
                beautifiedJson = writer.writeValueAsString(json);
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }
            body = byteArray(beautifiedJson.getBytes(StandardCharsets.UTF_8));
        } else {
            body_str = body_str.replace("&", "\n&");
            body = byteArray(body_str);
        }
        this.ResponseEditor.setContents(body);
    }
    
    
}